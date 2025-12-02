package server

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"tunnel_pls/session"
	"tunnel_pls/utils"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

var BAD_GATEWAY_RESPONSE = []byte("HTTP/1.1 502 Bad Gateway\r\n" +
	"Content-Length: 11\r\n" +
	"Content-Type: text/plain\r\n\r\n" +
	"Bad Gateway")

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

type connResponseWriter struct {
	conn   net.Conn
	header http.Header
	wrote  bool
}

func (w *connResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *connResponseWriter) WriteHeader(statusCode int) {
	if w.wrote {
		return
	}
	w.wrote = true
	_, err := fmt.Fprintf(w.conn, "HTTP/1.1 %d %s\r\n", statusCode, http.StatusText(statusCode))
	if err != nil {
		log.Printf("Error writing HTTP response: %v", err)
		return
	}
	err = w.header.Write(w.conn)
	if err != nil {
		log.Printf("Error writing HTTP header: %v", err)
		return
	}
	_, err = fmt.Fprint(w.conn, "\r\n")
	if err != nil {
		log.Printf("Error writing HTTP header: %v", err)
		return
	}
}

func (w *connResponseWriter) Write(b []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	return w.conn.Write(b)
}

func (w *connResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	rw := bufio.NewReadWriter(
		bufio.NewReader(w.conn),
		bufio.NewWriter(w.conn),
	)
	return w.conn, rw, nil
}

type CustomWriter struct {
	RemoteAddr  net.Addr
	writer      io.Writer
	reader      io.Reader
	headerBuf   []byte
	buf         []byte
	Requests    []*RequestContext
	interaction *session.Interaction
}

type RequestContext struct {
	Host        string
	Path        string
	Method      string
	Chunked     bool
	Tail        []byte
	ContentSize int
	Written     int
}

func (cw *CustomWriter) Read(p []byte) (int, error) {
	read, err := cw.reader.Read(p)
	test := bytes.NewReader(p)
	reqhf, _ := NewRequestHeaderFactory(test)
	if reqhf != nil {
		cw.Requests = append(cw.Requests, &RequestContext{
			Host:        reqhf.Get("Host"),
			Path:        reqhf.Path,
			Method:      reqhf.Method,
			Chunked:     false,
			Tail:        make([]byte, 5),
			ContentSize: 0,
			Written:     0,
		})
	}
	return read, err
}

func NewCustomWriter(writer io.Writer, reader io.Reader, remoteAddr net.Addr) *CustomWriter {
	return &CustomWriter{
		RemoteAddr:  remoteAddr,
		writer:      writer,
		reader:      reader,
		buf:         make([]byte, 0, 4096),
		interaction: nil,
	}
}

var DELIMITER = []byte{0x0D, 0x0A, 0x0D, 0x0A} // HTTP HEADER DELIMITER `\r\n\r\n`
var requestLine = regexp.MustCompile(`^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT) \S+ HTTP/\d\.\d$`)
var responseLine = regexp.MustCompile(`^HTTP/\d\.\d \d{3} .+`)

func isHTTPHeader(buf []byte) bool {
	lines := bytes.Split(buf, []byte("\r\n"))
	if len(lines) < 1 {
		return false
	}
	startLine := string(lines[0])
	if !requestLine.MatchString(startLine) && !responseLine.MatchString(startLine) {
		return false
	}

	for _, line := range lines[1:] {
		if len(line) == 0 {
			break
		}
		if !bytes.Contains(line, []byte(":")) {
			return false
		}
	}
	return true
}

func (cw *CustomWriter) Write(p []byte) (int, error) {
	if len(p) == len(BAD_GATEWAY_RESPONSE) && bytes.Equal(p, BAD_GATEWAY_RESPONSE) {
		return cw.writer.Write(p)
	}

	cw.buf = append(cw.buf, p...)
	timestamp := time.Now().UTC().Format(time.RFC3339)
	// TODO: implement middleware buat cache system dll
	if idx := bytes.Index(cw.buf, DELIMITER); idx != -1 {
		header := cw.buf[:idx+len(DELIMITER)]
		body := cw.buf[idx+len(DELIMITER):]

		if isHTTPHeader(header) {
			resphf := NewResponseHeaderFactory(header)
			resphf.Set("Server", "Tunnel Please")

			if resphf.Get("Transfer-Encoding") == "chunked" {
				cw.Requests[0].Chunked = true
			}
			if resphf.Get("Content-Length") != "" {
				bodySize, err := strconv.Atoi(resphf.Get("Content-Length"))
				if err != nil {
					log.Printf("Error parsing Content-Length: %v", err)
					cw.Requests[0].ContentSize = -1
				} else {
					cw.Requests[0].ContentSize = bodySize
				}
			} else {
				cw.Requests[0].ContentSize = -1
			}

			header = resphf.Finalize()
			_, err := cw.writer.Write(header)
			if err != nil {
				return 0, err
			}

			if len(body) > 0 {
				_, err := cw.writer.Write(body)
				if err != nil {
					return 0, err
				}
			}
			req := cw.Requests[0]
			req.Written += len(body)

			if req.Chunked {
				req.Tail = append(req.Tail, p[len(p)-5:]...)
				if bytes.Equal(req.Tail, []byte("0\r\n\r\n")) {
					cw.interaction.SendMessage(fmt.Sprintf("\033[32m%s %s -> %s %s \033[0m\r\n", timestamp, cw.RemoteAddr.String(), req.Method, req.Path))
				}
			} else if req.ContentSize != -1 {
				if req.Written >= req.ContentSize {
					cw.Requests = cw.Requests[1:]
					cw.interaction.SendMessage(fmt.Sprintf("\033[32m%s %s -> %s %s \033[0m\r\n", timestamp, cw.RemoteAddr.String(), req.Method, req.Path))
				}
			} else {
				cw.Requests = cw.Requests[1:]
			}
			cw.buf = nil
			return len(p), nil
		}
	}
	cw.buf = nil
	n, err := cw.writer.Write(p)
	if err != nil {
		return n, err
	}

	req := cw.Requests[0]
	req.Written += len(p)
	if req.Chunked {
		req.Tail = append(req.Tail, p[len(p)-5:]...)
		if bytes.Equal(req.Tail, []byte("0\r\n\r\n")) {
			cw.Requests = cw.Requests[1:]
			cw.interaction.SendMessage(fmt.Sprintf("\033[32m%s %s -> %s %s \033[0m\r\n", timestamp, cw.RemoteAddr.String(), req.Method, req.Path))
		}
	} else if req.ContentSize != -1 {
		if req.Written >= req.ContentSize {
			cw.Requests = cw.Requests[1:]
			cw.interaction.SendMessage(fmt.Sprintf("\033[32m%s %s -> %s %s \033[0m\r\n", timestamp, cw.RemoteAddr.String(), req.Method, req.Path))
		}
	} else {
		cw.Requests = cw.Requests[1:]
	}

	return n, nil
}

func (cw *CustomWriter) AddInteraction(interaction *session.Interaction) {
	cw.interaction = interaction
}

var redirectTLS = false
var allowedCors = make(map[string]bool)
var isAllowedAllCors = false

func init() {
	corsList := utils.Getenv("cors_list")
	if corsList == "*" {
		isAllowedAllCors = true
	} else {
		for _, allowedOrigin := range strings.Split(corsList, ",") {
			allowedCors[allowedOrigin] = true
		}
	}
}

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
		log.Printf("Error creating request header: %v", err)
		return
	}

	host := strings.Split(reqhf.Get("Host"), ".")
	if len(host) < 1 {
		_, err := conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		if err != nil {
			log.Println("Failed to write 400 Bad Request:", err)
			return
		}
		return
	}

	slug := host[0]

	if redirectTLS {
		_, err := conn.Write([]byte("HTTP/1.1 301 Moved Permanently\r\n" +
			fmt.Sprintf("Location: https://%s.%s/\r\n", slug, utils.Getenv("domain")) +
			"Content-Length: 0\r\n" +
			"Connection: close\r\n" +
			"\r\n"))
		if err != nil {
			log.Println("Failed to write 301 Moved Permanently:", err)
			return
		}
		return
	}

	if slug == "ping" {
		// TODO: implement cors
		_, err := conn.Write([]byte(
			"HTTP/1.1 200 OK\r\n" +
				"Content-Length: 0\r\n" +
				"Connection: close\r\n" +
				"Access-Control-Allow-Origin: *\r\n" +
				"Access-Control-Allow-Methods: GET, HEAD, OPTIONS\r\n" +
				"Access-Control-Allow-Headers: *\r\n" +
				"\r\n",
		))
		if err != nil {
			log.Println("Failed to write 200 OK:", err)
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
	cw := NewCustomWriter(conn, dstReader, conn.RemoteAddr())

	// Initial Requests
	cw.Requests = append(cw.Requests, &RequestContext{
		Host:    reqhf.Get("Host"),
		Path:    reqhf.Path,
		Method:  reqhf.Method,
		Chunked: false,
	})
	forwardRequest(cw, reqhf, sshSession)
	return
}

func forwardRequest(cw *CustomWriter, initialRequest *RequestHeaderFactory, sshSession *session.SSHSession) {
	cw.AddInteraction(sshSession.Interaction)
	originHost, originPort := ParseAddr(cw.RemoteAddr.String())
	payload := createForwardedTCPIPPayload(originHost, uint16(originPort), sshSession.Forwarder.GetForwardedPort())
	channel, reqs, err := sshSession.Conn.OpenChannel("forwarded-tcpip", payload)
	if err != nil {
		log.Printf("Failed to open forwarded-tcpip channel: %v", err)
		sendBadGatewayResponse(cw)
		return
	}
	defer func(channel ssh.Channel) {
		err := channel.Close()
		if err != nil {
			if errors.Is(err, io.EOF) {
				sendBadGatewayResponse(cw)
				return
			}
			log.Println("Failed to close connection:", err)
			return
		}
	}(channel)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("Panic in request handler: %v", r)
			}
		}()
		for req := range reqs {
			err := req.Reply(false, nil)
			if err != nil {
				log.Printf("Failed to reply to request: %v", err)
				return
			}
		}
	}()

	_, err = channel.Write(initialRequest.Finalize())
	if err != nil {
		log.Printf("Failed to write forwarded-tcpip:", err)
		return
	}

	sshSession.HandleForwardedConnection(cw, channel, cw.RemoteAddr)
	return
}

func sendBadGatewayResponse(writer io.Writer) {
	_, err := writer.Write(BAD_GATEWAY_RESPONSE)
	if err != nil {
		log.Printf("failed to write Bad Gateway response: %v", err)
		return
	}
}
