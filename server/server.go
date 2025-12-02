package server

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"tunnel_pls/utils"

	"golang.org/x/crypto/ssh"
)

type Server struct {
	Conn       *net.Listener
	Config     *ssh.ServerConfig
	HttpServer *http.Server
}

func NewServer(config ssh.ServerConfig) *Server {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%s", utils.Getenv("port")))
	if err != nil {
		log.Fatalf("failed to listen on port 2200: %v", err)
		return nil
	}
	if utils.Getenv("tls_enabled") == "true" {
		go func() {
			err := NewHTTPSServer()
			if err != nil {
				log.Fatalf("failed to start https server: %v", err)
			}
			return
		}()
	}
	go func() {
		err := NewHTTPServer()
		if err != nil {
			log.Fatalf("failed to start http server: %v", err)
		}
	}()
	return &Server{
		Conn:   &listener,
		Config: &config,
	}
}

func (s *Server) Start() {
	log.Println("SSH server is starting on port 2200...")
	for {
		conn, err := (*s.Conn).Accept()
		if err != nil {
			log.Printf("failed to accept connection: %v", err)
			continue
		}

		go s.handleConnection(conn)
	}
}

func createForwardedTCPIPPayload(host string, originPort, port uint16) []byte {
	var buf bytes.Buffer

	writeSSHString(&buf, "localhost")
	err := binary.Write(&buf, binary.BigEndian, uint32(port))
	if err != nil {
		log.Printf("Failed to write string to buffer: %v", err)
		return nil
	}
	writeSSHString(&buf, host)
	err = binary.Write(&buf, binary.BigEndian, uint32(originPort))
	if err != nil {
		log.Printf("Failed to write string to buffer: %v", err)
		return nil
	}

	return buf.Bytes()
}

func writeSSHString(buffer *bytes.Buffer, str string) {
	err := binary.Write(buffer, binary.BigEndian, uint32(len(str)))
	if err != nil {
		log.Printf("Failed to write string to buffer: %v", err)
		return
	}
	buffer.WriteString(str)
}

func ParseAddr(addr string) (string, uint32) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		log.Printf("Failed to parse origin address: %s from address %s", err.Error(), addr)
		return "0.0.0.0", uint32(0)
	}
	port, _ := strconv.Atoi(portStr)
	return host, uint32(port)
}
