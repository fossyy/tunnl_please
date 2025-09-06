package server

import (
	"bufio"
	"crypto/tls"
	"errors"
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

	if len(host) < 1 {
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		conn.Close()
		return
	}
	slug := host[0]

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
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		conn.Close()
		return
	}

	sshSession.HandleForwardedConnection(session.UserConnection{
		Reader: reader,
		Writer: conn,
	}, sshSession.Connection)
	return
}
