package session

import (
	"bytes"
	"log"
	"net"
	"sync"

	"golang.org/x/crypto/ssh"
)

const (
	INITIALIZING SessionStatus = "INITIALIZING"
	RUNNING      SessionStatus = "RUNNING"
	SETUP        SessionStatus = "SETUP"
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

type InteractionController interface {
	SendMessage(message string)
	HandleUserInput()
	HandleCommand(conn ssh.Channel, command string, inSlugEditMode *bool, editSlug *string, buf *bytes.Buffer)
	HandleSlugEditMode(conn ssh.Channel, inSlugEditMode *bool, editSlug *string, char byte, buf *bytes.Buffer)
	HandleSlugSave(conn ssh.Channel, inSlugEditMode *bool, editSlug *string, buf *bytes.Buffer)
	HandleSlugCancel(conn ssh.Channel, inSlugEditMode *bool, buf *bytes.Buffer)
	HandleSlugUpdateError()
	ShowWelcomeMessage()
	DisplaySlugEditor()
}

type ForwardingController interface {
	HandleGlobalRequest(ch <-chan *ssh.Request)
	HandleTCPIPForward(req *ssh.Request)
	HandleHTTPForward(req *ssh.Request, port uint16)
	HandleTCPForward(req *ssh.Request, addr string, port uint16)
	AcceptTCPConnections()
}

type Session interface {
	SessionLifecycle
	InteractionController
	ForwardingController
}

type Lifecycle struct {
	Status SessionStatus
}

type Forwarder struct {
	Listener      net.Listener
	TunnelType    TunnelType
	ForwardedPort uint16

	getSlug func() string
	setSlug func(string)
}

type ForwarderInfo interface {
	GetTunnelType() TunnelType
	GetForwardedPort() uint16
}

func (f *Forwarder) GetTunnelType() TunnelType {
	return f.TunnelType
}

func (f *Forwarder) GetForwardedPort() uint16 {
	return f.ForwardedPort
}

type Interaction struct {
	CommandBuffer *bytes.Buffer
	EditMode      bool
	EditSlug      string
	channel       ssh.Channel

	getSlug func() string
	setSlug func(string)

	session SessionCloser

	forwarder ForwarderInfo
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
