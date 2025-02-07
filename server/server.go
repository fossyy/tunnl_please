package server

import (
	"crypto/tls"
	"fmt"
	"golang.org/x/crypto/ssh"
	"log"
	"net"
	"net/http"
	httpServer "tunnel_pls/http"
	"tunnel_pls/utils"
)

type Server struct {
	Conn       *net.Listener
	Config     *ssh.ServerConfig
	HttpServer *http.Server
}

func NewServer(config ssh.ServerConfig) *Server {
	listener, err := net.Listen("tcp", ":2200")
	if err != nil {
		log.Fatalf("failed to listen on port 2200: %v", err)
		return nil
	}
	go httpServer.Listen()
	if utils.Getenv("tls_enabled") == "true" {
		cert, err := tls.LoadX509KeyPair(utils.Getenv("cert_loc"), utils.Getenv("key_loc"))
		if err != nil {
			log.Fatal("Failed to load key pair:", err)
		}

		tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}
		go httpServer.ListenTLS(tlsConfig)
	}
	return &Server{
		Conn:   &listener,
		Config: &config,
	}
}

func (s *Server) Start() {
	fmt.Println("SSH server is starting on port 2200...")
	for {
		conn, err := (*s.Conn).Accept()
		if err != nil {
			log.Printf("failed to accept connection: %v", err)
			continue
		}

		go s.handleConnection(conn)
	}
}
