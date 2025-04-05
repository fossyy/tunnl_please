package server

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"golang.org/x/net/context"
	"log"
	"net"
	"strings"
	"time"
	"tunnel_pls/session"
)

func NewHTTPSServer() error {
	cert, err := tls.LoadX509KeyPair("certs/localhost.direct.SS.crt", "certs/localhost.direct.SS.key")
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
	ctx, _ := context.WithDeadline(context.Background(), time.Now().Add(30*time.Second))
	reader := bufio.NewReader(conn)
	headers, err := peekUntilHeaders(reader, 512)
	if err != nil {
		fmt.Println("Failed to peek headers:", err)
		return
	}

	host := strings.Split(parseHostFromHeader(headers), ".")
	if len(host) < 1 {
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		fmt.Println("Bad Request")
		conn.Close()
		return
	}

	if len(host) < 1 {
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		fmt.Println("Bad Request")
		conn.Close()
		return
	}
	slug := host[0]

	sshSession, ok := session.Clients[slug]
	if !ok {
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		fmt.Println("Bad Request 1")
		conn.Close()
		return
	}

	sshSession.HandleForwardedConnection(session.UserConnection{
		Reader:  reader,
		Writer:  conn,
		Context: ctx,
	}, sshSession.Connection, 80)
	return
}
