package server

import (
	"bufio"
	"crypto/tls"
	"errors"
	"golang.org/x/net/context"
	"log"
	"net"
	"strings"
	"time"
	"tunnel_pls/session"
	"tunnel_pls/utils"
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

	sshSession, ok := session.Clients[slug]
	if !ok {
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		conn.Close()
		return
	}
	keepalive, timeout := parseConnectionDetails(headers)
	var ctx context.Context
	var cancel context.CancelFunc
	if keepalive {
		if timeout >= 300 {
			timeout = 300
		}
		ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(time.Duration(timeout)*time.Second))
	} else {
		ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(5*time.Second))
	}

	sshSession.HandleForwardedConnection(session.UserConnection{
		Reader:  reader,
		Writer:  conn,
		Context: ctx,
		Cancel:  cancel,
	}, sshSession.Connection)
	return
}
