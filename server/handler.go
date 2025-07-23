package server

import (
	"golang.org/x/crypto/ssh"
	"log"
	"net"
	"tunnel_pls/session"
)

func (s *Server) handleConnection(conn net.Conn) {
	sshConn, chans, forwardingReqs, err := ssh.NewServerConn(conn, s.Config)
	if err != nil {
		log.Printf("failed to establish SSH connection: %v", err)
		err := conn.Close()
		if err != nil {
			log.Printf("failed to close SSH connection: %v", err)
			return
		}
		return
	}

	log.Println("SSH connection established:", sshConn.User())

	newSession := session.New(sshConn, forwardingReqs)
	for ch := range chans {
		newSession.ChannelChan <- ch
	}

	defer func(newSession *session.Session) {
		err := newSession.Close()
		if err != nil {
			log.Printf("failed to close session: %v", err)
		}
	}(newSession)
	return
}
