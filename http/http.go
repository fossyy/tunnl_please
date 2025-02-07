package httpServer

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"tunnel_pls/session"
	"tunnel_pls/utils"
	indexView "tunnel_pls/view/index"
)

type RouteHandler http.HandlerFunc

// Simple Router Struct
type Router struct {
	routes map[string]map[string]http.Handler
}

// NewRouter initializes a new router
func NewRouter() *Router {
	return &Router{
		routes: make(map[string]map[string]http.Handler),
	}
}

// Handle registers a route with an http.Handler
func (r *Router) Handle(method, path string, handler http.Handler) {
	if _, exists := r.routes[method]; !exists {
		r.routes[method] = make(map[string]http.Handler)
	}
	r.routes[method][path] = handler
}

// HandleFunc registers a route with a function
func (r *Router) HandleFunc(method, path string, handlerFunc func(http.ResponseWriter, *http.Request)) {
	r.Handle(method, path, http.HandlerFunc(handlerFunc))
}

func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if methodRoutes, exists := r.routes[req.Method]; exists {
		if handler, exists := methodRoutes[req.URL.Path]; exists {
			handler.ServeHTTP(w, req)
			return
		}
	}
	http.Error(w, "404 Not Found", http.StatusNotFound)
}

type tcpResponseWriter struct {
	conn   net.Conn
	header http.Header
	status int
}

func (w *tcpResponseWriter) Header() http.Header {
	return w.header
}

func (w *tcpResponseWriter) WriteHeader(statusCode int) {
	w.status = statusCode
}

func (w *tcpResponseWriter) Write(data []byte) (int, error) {
	fmt.Println("here")
	resp := fmt.Sprintf("HTTP/1.1 %d %s\r\n", w.status, http.StatusText(w.status))
	for k, v := range w.header {
		resp += fmt.Sprintf("%s: %s\r\n", k, v[0])
	}
	resp += "\r\n" + string(data)

	return w.conn.Write([]byte(resp))
}

var router = NewRouter()

func Listen() {
	server, err := net.Listen("tcp", ":80")

	if err != nil {
		log.Fatal(err)
		return
	}

	router.HandleFunc("GET", "/", func(w http.ResponseWriter, r *http.Request) {
		indexView.Main("Main Page", utils.Getenv("domain")).Render(r.Context(), w)
		return
	})

	router.HandleFunc("GET", "/public/output.css", func(w http.ResponseWriter, r *http.Request) {
		open, err := os.Open("public/output.css")
		if err != nil {
			return
		}
		data, _ := io.ReadAll(open)
		fmt.Fprintf(w, string(data))
	})

	//fileserver := http.FileServer(http.Dir("./public"))
	//router.Handle("/public/", http.StripPrefix("/public", fileserver))

	defer server.Close()
	log.Println("Listening on :80")
	for {
		conn, err := server.Accept()
		if err != nil {
			log.Fatal(err)
			return
		}

		go handleRequest(conn)
	}
}

func handleRequest(conn net.Conn) {
	defer conn.Close()
	var rawRequest string

	reader := bufio.NewReader(conn)
	r, err := http.ReadRequest(reader)
	if err != nil {
		fmt.Println("Error reading request:", err)
		return
	}

	if r.Host == utils.Getenv("domain") {
		writer := &tcpResponseWriter{
			conn:   conn,
			header: make(http.Header),
			status: http.StatusOK,
		}
		fmt.Println(r.Pattern)
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
