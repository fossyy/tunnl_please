package server

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"golang.org/x/net/context"
	"log"
	"net"
	"strconv"
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
	reader := bufio.NewReader(conn)
	headers, err := peekUntilHeaders(reader, 8192)
	if err != nil {
		log.Println("Failed to peek headers:", err)
		return
	}

	host := strings.Split(parseHostFromHeader(headers), ".")
	if len(host) < 1 {
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		log.Println("Bad Request")
		conn.Close()
		return
	}

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

func parseConnectionDetails(data []byte) (keepAlive bool, timeout int) {
	keepAlive = false
	timeout = 30

	lines := strings.Split(string(data), "\r\n")

	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), "connection:") {
			value := strings.TrimSpace(strings.TrimPrefix(strings.ToLower(line), "connection:"))
			keepAlive = (value == "keep-alive")
			break
		}
	}

	if keepAlive {
		for _, line := range lines {
			if strings.HasPrefix(strings.ToLower(line), "keep-alive:") {
				value := strings.TrimSpace(strings.TrimPrefix(line, "Keep-Alive:"))

				if strings.Contains(value, "timeout=") {
					parts := strings.Split(value, ",")
					for _, part := range parts {
						part = strings.TrimSpace(part)
						if strings.HasPrefix(part, "timeout=") {
							timeoutStr := strings.TrimPrefix(part, "timeout=")
							if t, err := strconv.Atoi(timeoutStr); err == nil {
								timeout = t
							}
						}
					}
				}
				break
			}
		}
	}

	return keepAlive, timeout
}
