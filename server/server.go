package server

import (
	"fmt"
	"log"
	"net"
	"net/http"
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
