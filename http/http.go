package httpServer

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"tunnel_pls/session"
)

func Listen() {
	server := http.Server{
		Addr: ":80",
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		var rawRequest string
		slug := strings.Split(r.Host, ".")[0]
		if slug == "" {
			http.Error(w, "You fuck up man", http.StatusBadRequest)
			return
		}
		sshSession, ok := session.Clients[slug]
		if !ok {
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
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

		host, originPort := session.ParseAddr(r.RemoteAddr)
		data := sshSession.GetForwardedConnection(host, sshSession.Connection, payload, originPort, 80)

		response, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(data)), r)
		if err != nil {
			return
		}
		var isServerSet = false
		for k, v := range response.Header {
			if k == "Server" {
				isServerSet = true
				w.Header().Set(k, fmt.Sprintf("Tunnel_Pls/%v", response.Header[k][0]))
				continue
			}
			w.Header().Set(k, v[0])
		}
		if !isServerSet {
			w.Header().Set("Server", "Tunnel_Pls")
		}
		w.WriteHeader(response.StatusCode)
		io.Copy(w, response.Body)
	})

	fmt.Println("Listening on port 80")
	server.ListenAndServe()
}
