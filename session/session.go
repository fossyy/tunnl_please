package session

import (
	"bytes"
	"log"
	"sync"

	"golang.org/x/crypto/ssh"
)

const (
	INITIALIZING Status = "INITIALIZING"
	RUNNING      Status = "RUNNING"
	SETUP        Status = "SETUP"
)

type TunnelType string

const (
	HTTP TunnelType = "http"
	TCP  TunnelType = "tcp"
)

type SessionLifecycle interface {
	Close() error
	WaitForRunningStatus()
}

type SessionCloser interface {
	Close() error
}

type Session interface {
	SessionLifecycle
	InteractionController
	ForwardingController
}

type Lifecycle struct {
	Status Status
}

type SSHSession struct {
	Lifecycle   *Lifecycle
	Interaction *Interaction
	Forwarder   *Forwarder

	Conn    *ssh.ServerConn
	channel ssh.Channel

	slug   string
	slugMu sync.RWMutex
}

func New(conn *ssh.ServerConn, forwardingReq <-chan *ssh.Request, sshChan <-chan ssh.NewChannel) {
	session := SSHSession{
		Lifecycle: &Lifecycle{
			Status: INITIALIZING,
		},
		Interaction: &Interaction{
			CommandBuffer: new(bytes.Buffer),
			EditMode:      false,
			EditSlug:      "",
			channel:       nil,
			getSlug:       nil,
			setSlug:       nil,
			session:       nil,
			forwarder:     nil,
		},
		Forwarder: &Forwarder{
			Listener:      nil,
			TunnelType:    "",
			ForwardedPort: 0,
			getSlug:       nil,
			setSlug:       nil,
		},
		Conn:    conn,
		channel: nil,
		slug:    "",
	}

	session.Forwarder.getSlug = session.GetSlug
	session.Forwarder.setSlug = session.SetSlug
	session.Interaction.getSlug = session.GetSlug
	session.Interaction.setSlug = session.SetSlug
	session.Interaction.session = &session
	session.Interaction.forwarder = session.Forwarder

	go func() {
		go session.waitForRunningStatus()

		for channel := range sshChan {
			ch, reqs, _ := channel.Accept()
			if session.channel == nil {
				session.channel = ch
				session.Interaction.channel = ch
				session.Lifecycle.Status = SETUP
				go session.HandleGlobalRequest(forwardingReq)
			}
			go session.HandleGlobalRequest(reqs)
		}
		err := session.Close()
		if err != nil {
			log.Printf("failed to close session: %v", err)
		}
		return
	}()
}

func (s *SSHSession) GetSlug() string {
	s.slugMu.RLock()
	defer s.slugMu.RUnlock()
	return s.slug
}

func (s *SSHSession) SetSlug(slug string) {
	s.slugMu.Lock()
	s.slug = slug
	s.slugMu.Unlock()
}
