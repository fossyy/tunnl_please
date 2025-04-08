package server

import (
	"golang.org/x/crypto/ssh"
	"log"
	"net"
	"tunnel_pls/session"
)

func (s *Server) handleConnection(conn net.Conn) {
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, s.Config)
	if err != nil {
		log.Printf("failed to establish SSH connection: %v", err)
		conn.Close()
		return
	}

	log.Println("SSH connection established:", sshConn.User())

	session.New(sshConn, chans, reqs)
}
