package server

import (
	"fmt"
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

	fmt.Println("SSH connection established:", sshConn.User())

	session.New(sshConn, chans, reqs)
}
