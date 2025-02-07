package session

import (
	"fmt"
	"golang.org/x/crypto/ssh"
	"net"
)

type Session struct {
	ConnChannels  []ssh.Channel
	Connection    *ssh.ServerConn
	GlobalRequest <-chan *ssh.Request
	Listener      net.Listener
	TunnelType    TunnelType
	Done          chan bool
}

type TunnelType string

const (
	HTTP    TunnelType = "http"
	TCP     TunnelType = "tcp"
	UDP     TunnelType = "udp"
	UNKNOWN TunnelType = "unknown"
)

var Clients map[string]*Session

func init() {
	Clients = make(map[string]*Session)
}

func New(conn *ssh.ServerConn, sshChannel <-chan ssh.NewChannel, req <-chan *ssh.Request) *Session {
	session := &Session{
		ConnChannels:  []ssh.Channel{},
		Connection:    conn,
		GlobalRequest: req,
		TunnelType:    UNKNOWN,
		Done:          make(chan bool),
	}

	go func() {
		for newChannel := range sshChannel {
			go session.HandleSessionChannel(newChannel)
		}
	}()

	return session
}

func (session *Session) Close() {
	session.Done <- true
	if session.TunnelType != HTTP {
		session.Listener.Close()
	}

	for _, ch := range session.ConnChannels {
		if err := ch.Close(); err != nil {
			fmt.Println("Error closing channel : ", err.Error())
			continue
		}
	}

	if err := session.Connection.Close(); err != nil {
		fmt.Println("Error closing connection : ", err.Error())
	}
}
