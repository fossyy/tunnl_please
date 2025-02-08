package httpServer

import (
	"crypto/tls"
	"fmt"
	"golang.org/x/net/http2"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"tunnel_pls/session"
	"tunnel_pls/utils"
	indexView "tunnel_pls/view/index"
)

func ListenTLS(config *tls.Config) {
	server := &http.Server{
		Addr:      ":443",
		TLSConfig: config,
		Handler:   http.HandlerFunc(handleRequestTLS),
	}

	http2.ConfigureServer(server, &http2.Server{})

	fmt.Println("Listening on :8443 (HTTP/2 over TLS)")
	log.Fatal(server.ListenAndServeTLS("", ""))
}

func handleRequestTLS(w http.ResponseWriter, r *http.Request) {
	_, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request", http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	var rawRequest string

	if r.Host == utils.Getenv("domain") {
		TLSRouter().ServeHTTP(w, r)
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

	rawRequest += fmt.Sprintf("%s %s %s\r\n", r.Method, r.URL.RequestURI(), "HTTP/1.1")
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
	response := sshSession.GetForwardedConnectionTLS(host, sshSession.Connection, payload, originPort, 80, r.RequestURI, r.Method, r.Proto)

	forbiddenHeaders := map[string]bool{
		"connection":        true,
		"transfer-encoding": true,
		"upgrade":           true,
		"keep-alive":        true,
	}

	for k, v := range response.Header {
		k = strings.ToLower(k)

		if forbiddenHeaders[k] {
			continue
		}

		if k == ":status" || k == ":method" || k == ":path" || k == ":authority" {
			continue
		}

		w.Header().Set(k, v[0])
	}

	io.Copy(w, response.Body)
	return
}

func TLSRouter() *http.ServeMux {
	handler := http.NewServeMux()
	handler.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		indexView.Main("Main Page", utils.Getenv("domain")).Render(r.Context(), w)
		return
	})

	handler.HandleFunc("/public/output.css", func(w http.ResponseWriter, r *http.Request) {
		open, err := os.Open("public/output.css")
		if err != nil {
			return
		}
		defer open.Close()
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		io.Copy(w, open)
		return
	})
	return handler
}

//func handleRequestTLS(conn net.Conn) {
//	defer conn.Close()
//	var rawRequest string
//
//	reader := bufio.NewReader(conn)
//	r, err := http.ReadRequest(reader)
//	if err != nil {
//		fmt.Println("Error reading request:", err)
//		return
//	}
//
//	writer := &tcpResponseWriter{
//		conn:   conn,
//		header: make(http.Header),
//		status: http.StatusOK,
//	}
//
//	if r.Host == utils.Getenv("domain") {
//		router.ServeHTTP(writer, r)
//		return
//	}
//
//	slug := strings.Split(r.Host, ".")[0]
//	if slug == "" {
//		fmt.Println("Error parsing slug: ", r.Host)
//		return
//	}
//
//	sshSession, ok := session.Clients[slug]
//	if !ok {
//		fmt.Println("Error finding ssh session: ", slug)
//		return
//	}
//
//	rawRequest += fmt.Sprintf("%s %s %s\r\n", r.Method, r.URL.RequestURI(), r.Proto)
//	rawRequest += fmt.Sprintf("Host: %s\r\n", r.Host)
//
//	for k, v := range r.Header {
//		rawRequest += fmt.Sprintf("%s: %s\r\n", k, v[0])
//	}
//	rawRequest += "\r\n"
//
//	if r.Body != nil {
//		body, err := io.ReadAll(r.Body)
//		if err != nil {
//			log.Println("Error reading request body:", err)
//		} else {
//			rawRequest += string(body)
//		}
//	}
//
//	payload := []byte(rawRequest)
//
//	host, originPort := session.ParseAddr(conn.RemoteAddr().String())
//	sshSession.GetForwardedConnection(conn, host, sshSession.Connection, payload, originPort, 80, r.RequestURI, r.Method, r.Proto)
//}
