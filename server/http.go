package server

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"golang.org/x/net/context"
	"log"
	"net"
	"strings"
	"time"
	"tunnel_pls/session"
	"tunnel_pls/utils"
)

var redirectTLS bool = false

func NewHTTPServer() error {
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
	//TODO: Determain deadline time/set custom timeout on env
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

	if redirectTLS {
		conn.Write([]byte("HTTP/1.1 301 Moved Permanently\r\n" +
			fmt.Sprintf("Location: https://%s.%s/\r\n", slug, utils.Getenv("domain")) +
			"Content-Length: 0\r\n" +
			"Connection: close\r\n" +
			"\r\n"))
		conn.Close()
		return
	}

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
