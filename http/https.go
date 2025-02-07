package httpServer

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"tunnel_pls/session"
	"tunnel_pls/utils"
)

func ListenTLS(config *tls.Config) {
	server, err := tls.Listen("tcp", ":443", config)
	if err != nil {
		return
	}

	if err != nil {
		log.Fatal(err)
		return
	}

	defer server.Close()
	log.Println("Listening on :443")
	for {
		conn, err := server.Accept()
		if err != nil {
			log.Fatal(err)
			return
		}

		go handleRequestTLS(conn)
	}
}

func handleRequestTLS(conn net.Conn) {
	defer conn.Close()
	var rawRequest string

	reader := bufio.NewReader(conn)
	r, err := http.ReadRequest(reader)
	if err != nil {
		fmt.Println("Error reading request:", err)
		return
	}

	writer := &tcpResponseWriter{
		conn:   conn,
		header: make(http.Header),
		status: http.StatusOK,
	}

	if r.Host == utils.Getenv("domain") {
		router.ServeHTTP(writer, r)
		return
	}

	slug := strings.Split(r.Host, ".")[0]
	if slug == "" {
		fmt.Println("Error parsing slug: ", r.Host)
		return
	}

	sshSession, ok := session.Clients[slug]
	if !ok {
		fmt.Println("Error finding ssh session: ", slug)
		return
	}

	rawRequest += fmt.Sprintf("%s %s %s\r\n", r.Method, r.URL.RequestURI(), r.Proto)
	rawRequest += fmt.Sprintf("Host: %s\r\n", r.Host)

	for k, v := range r.Header {
		rawRequest += fmt.Sprintf("%s: %s\r\n", k, v[0])
	}
	rawRequest += "\r\n"

	if r.Body != nil {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			log.Println("Error reading request body:", err)
		} else {
			rawRequest += string(body)
		}
	}

	payload := []byte(rawRequest)

	host, originPort := session.ParseAddr(conn.RemoteAddr().String())
	sshSession.GetForwardedConnection(conn, host, sshSession.Connection, payload, originPort, 80, r.RequestURI, r.Method, r.Proto)
}
