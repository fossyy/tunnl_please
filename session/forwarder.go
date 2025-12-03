package session

import (
	"net"

	"golang.org/x/crypto/ssh"
)

type Forwarder struct {
	Listener      net.Listener
	TunnelType    TunnelType
	ForwardedPort uint16

	getSlug func() string
	setSlug func(string)
}

type ForwardingController interface {
	HandleGlobalRequest(ch <-chan *ssh.Request)
	HandleTCPIPForward(req *ssh.Request)
	HandleHTTPForward(req *ssh.Request, port uint16)
	HandleTCPForward(req *ssh.Request, addr string, port uint16)
	AcceptTCPConnections()
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
