package session

import (
	"golang.org/x/crypto/ssh"
)

type TunnelType string

const (
	HTTP    TunnelType = "http"
	TCP     TunnelType = "tcp"
	UDP     TunnelType = "udp"
	UNKNOWN TunnelType = "unknown"
)

func New(conn *ssh.ServerConn, sshChannel <-chan ssh.NewChannel, req <-chan *ssh.Request) *Session {
	session := &Session{
		Status:      SETUP,
		Slug:        "",
		ConnChannel: nil,
		Connection:  conn,
		TunnelType:  UNKNOWN,
		Done:        make(chan bool),
	}

	go func() {
		for newChannel := range sshChannel {
			go session.HandleSessionChannel(newChannel, req)
		}
	}()

	return session
}
