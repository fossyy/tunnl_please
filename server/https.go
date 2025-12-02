package server

import (
	"bufio"
	"crypto/tls"
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

func NewHTTPSServer() error {
	cert, err := tls.LoadX509KeyPair(utils.Getenv("cert_loc"), utils.Getenv("key_loc"))
	if err != nil {
		return err
	}

	config := &tls.Config{Certificates: []tls.Certificate{cert}}
	ln, err := tls.Listen("tcp", ":443", config)
	if err != nil {
		return err
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					log.Println("https server closed")
				}
				log.Printf("Error accepting connection: %v", err)
				continue
			}

			go HandlerTLS(conn)
		}
	}()
	return nil
}

func HandlerTLS(conn net.Conn) {
	defer func() {
		err := conn.Close()
		if err != nil {
			log.Printf("Error closing connection: %v", err)
			return
		}
		return
	}()

	dstReader := bufio.NewReader(conn)
	reqhf, err := NewRequestHeaderFactory(dstReader)
	if err != nil {
		return
	}
	cw := NewCustomWriter(conn, dstReader, conn.RemoteAddr())

	// Initial Requests
	cw.Requests = append(cw.Requests, &RequestContext{
		Host:    reqhf.Get("Host"),
		Path:    reqhf.Path,
		Method:  reqhf.Method,
		Chunked: false,
	})

	host := strings.Split(reqhf.Get("Host"), ".")
	if len(host) < 1 {
		_, err := conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		if err != nil {
			log.Println("Failed to write 400 Bad Request:", err)
			return
		}
		err = conn.Close()
		if err != nil {
			log.Println("Failed to close connection:", err)
			return
		}
		return
	}

	slug := host[0]

	if slug == "ping" {
		req, err := http.ReadRequest(dstReader)
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
		_, err := conn.Write([]byte("HTTP/1.1 301 Moved Permanently\r\n" +
			fmt.Sprintf("Location: https://tunnl.live/tunnel-not-found?slug=%s\r\n", slug) +
			"Content-Length: 0\r\n" +
			"Connection: close\r\n" +
			"\r\n"))
		if err != nil {
			log.Println("Failed to write 301 Moved Permanently:", err)
			return
		}
		err = conn.Close()
		if err != nil {
			log.Println("Failed to close connection:", err)
			return
		}
		return
	}
	forwardRequest(cw, reqhf, sshSession)
	return
}
