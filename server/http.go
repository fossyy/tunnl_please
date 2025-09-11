package server

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"tunnel_pls/session"
	"tunnel_pls/utils"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

type connResponseWriter struct {
	conn   net.Conn
	header http.Header
	wrote  bool
}

func (w *connResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *connResponseWriter) WriteHeader(statusCode int) {
	if w.wrote {
		return
	}
	w.wrote = true
	fmt.Fprintf(w.conn, "HTTP/1.1 %d %s\r\n", statusCode, http.StatusText(statusCode))
	w.header.Write(w.conn)
	fmt.Fprint(w.conn, "\r\n")
}

func (w *connResponseWriter) Write(b []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	return w.conn.Write(b)
}

func (w *connResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	rw := bufio.NewReadWriter(
		bufio.NewReader(w.conn),
		bufio.NewWriter(w.conn),
	)
	return w.conn, rw, nil
}

var redirectTLS = false
var allowedCors = make(map[string]bool)
var isAllowedAllCors = false

func init() {
	corsList := utils.Getenv("cors_list")
	if corsList == "*" {
		isAllowedAllCors = true
	} else {
		for _, allowedOrigin := range strings.Split(corsList, ",") {
			allowedCors[allowedOrigin] = true
		}
	}
}

func NewHTTPServer() error {
	upgrader.CheckOrigin = func(r *http.Request) bool {
		if isAllowedAllCors {
			return true
		} else {
			isAllowed, ok := allowedCors[r.Header.Get("Origin")]
			if !ok || !isAllowed {
				return false
			}
			return true
		}
	}

	listener, err := net.Listen("tcp", ":80")
	if err != nil {
		return errors.New("Error listening: " + err.Error())
	}
	if utils.Getenv("tls_enabled") == "true" && utils.Getenv("tls_redirect") == "true" {
		redirectTLS = true
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				log.Printf("Error accepting connection: %v", err)
				continue
			}

			go Handler(conn)
		}
	}()
	return nil
}

func Handler(conn net.Conn) {
	reader := bufio.NewReader(conn)
	headers, err := peekUntilHeaders(reader, 8192)
	if err != nil {
		log.Println("Failed to peek headers:", err)
		return
	}

	host := strings.Split(parseHostFromHeader(headers), ".")
	if len(host) < 1 {
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		conn.Close()
		return
	}

	slug := host[0]

	if redirectTLS {
		conn.Write([]byte("HTTP/1.1 301 Moved Permanently\r\n" +
			fmt.Sprintf("Location: https://%s.%s/\r\n", slug, utils.Getenv("domain")) +
			"Content-Length: 0\r\n" +
			"Connection: close\r\n" +
			"\r\n"))
		conn.Close()
		return
	}

	if slug == "ping" {
		req, err := http.ReadRequest(reader)
		if err != nil {
			log.Println("failed to parse HTTP request:", err)
			return
		}
		rw := &connResponseWriter{conn: conn}

		wsConn, err := upgrader.Upgrade(rw, req, nil)
		if err != nil {
			if !strings.Contains(err.Error(), "the client is not using the websocket protocol") {
				log.Println("Upgrade failed:", err)
			}
			err := conn.Close()
			if err != nil {
				log.Println("failed to close connection:", err)
				return
			}
			return
		}

		err = wsConn.WriteMessage(websocket.TextMessage, []byte("pong"))
		if err != nil {
			log.Println("failed to write pong:", err)
			return
		}
		err = wsConn.Close()
		if err != nil {
			log.Println("websocket close failed :", err)
			return
		}
		return
	}

	sshSession, ok := session.Clients[slug]
	if !ok {
		conn.Write([]byte("HTTP/1.1 301 Moved Permanently\r\n" +
			fmt.Sprintf("Location: https://tunnl.live/tunnel-not-found?slug=%s\r\n", slug) +
			"Content-Length: 0\r\n" +
			"Connection: close\r\n" +
			"\r\n"))
		conn.Close()
		return
	}

	sshSession.HandleForwardedConnection(session.UserConnection{
		Reader: reader,
		Writer: conn,
	}, sshSession.Connection)
	return
}

func peekUntilHeaders(reader *bufio.Reader, maxBytes int) ([]byte, error) {
	var buf []byte
	for {
		n := len(buf) + 1
		if n > maxBytes {
			return buf, nil
		}

		peek, err := reader.Peek(n)
		if err != nil {
			return nil, err
		}
		buf = peek

		if bytes.Contains(buf, []byte("\r\n\r\n")) {
			return buf, nil
		}
	}
}

func parseHostFromHeader(data []byte) string {
	lines := strings.Split(string(data), "\r\n")
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), "host:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "Host:"))
		}
	}
	return ""
}
