package forwarder

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"strconv"
	"tunnel_pls/session/slug"
	"tunnel_pls/types"

	"golang.org/x/crypto/ssh"
)

type Forwarder struct {
	Listener      net.Listener
	TunnelType    types.TunnelType
	ForwardedPort uint16
	SlugManager   slug.Manager
	Lifecycle     Lifecycle
}

type Lifecycle interface {
	GetConnection() ssh.Conn
}

type ForwardingController interface {
	AcceptTCPConnections()
	SetType(tunnelType types.TunnelType)
	GetTunnelType() types.TunnelType
	GetForwardedPort() uint16
	SetForwardedPort(port uint16)
	SetListener(listener net.Listener)
	GetListener() net.Listener
	Close() error
	HandleConnection(dst io.ReadWriter, src ssh.Channel, remoteAddr net.Addr)
	SetLifecycle(lifecycle Lifecycle)
	CreateForwardedTCPIPPayload(origin net.Addr) []byte
}

func (f *Forwarder) SetLifecycle(lifecycle Lifecycle) {
	f.Lifecycle = lifecycle
}

func (f *Forwarder) AcceptTCPConnections() {
	for {
		conn, err := f.GetListener().Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("Error accepting connection: %v", err)
			continue
		}
		payload := f.CreateForwardedTCPIPPayload(conn.RemoteAddr())
		channel, reqs, err := f.Lifecycle.GetConnection().OpenChannel("forwarded-tcpip", payload)
		if err != nil {
			log.Printf("Failed to open forwarded-tcpip channel: %v", err)
			return
		}

		go func() {
			for req := range reqs {
				err := req.Reply(false, nil)
				if err != nil {
					log.Printf("Failed to reply to request: %v", err)
					return
				}
			}
		}()
		go f.HandleConnection(conn, channel, conn.RemoteAddr())
	}
}

func (f *Forwarder) HandleConnection(dst io.ReadWriter, src ssh.Channel, remoteAddr net.Addr) {
	defer func(src ssh.Channel) {
		err := src.Close()
		if err != nil && !errors.Is(err, io.EOF) {
			log.Printf("Error closing connection: %v", err)
		}
	}(src)
	log.Printf("Handling new forwarded connection from %s", remoteAddr)

	go func() {
		_, err := io.Copy(src, dst)
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
			log.Printf("Error copying from conn.Reader to channel: %v", err)
		}
	}()

	_, err := io.Copy(dst, src)

	if err != nil && !errors.Is(err, io.EOF) {
		log.Printf("Error copying from channel to conn.Writer: %v", err)
	}
	return
}

func (f *Forwarder) SetType(tunnelType types.TunnelType) {
	f.TunnelType = tunnelType
}

func (f *Forwarder) GetTunnelType() types.TunnelType {
	return f.TunnelType
}

func (f *Forwarder) GetForwardedPort() uint16 {
	return f.ForwardedPort
}

func (f *Forwarder) SetForwardedPort(port uint16) {
	f.ForwardedPort = port
}

func (f *Forwarder) SetListener(listener net.Listener) {
	f.Listener = listener
}

func (f *Forwarder) GetListener() net.Listener {
	return f.Listener
}

func (f *Forwarder) Close() error {
	if f.GetTunnelType() != types.HTTP {
		return f.Listener.Close()
	}
	return nil
}

func (f *Forwarder) CreateForwardedTCPIPPayload(origin net.Addr) []byte {
	var buf bytes.Buffer

	host, originPort := parseAddr(origin.String())

	writeSSHString(&buf, "localhost")
	err := binary.Write(&buf, binary.BigEndian, uint32(f.GetForwardedPort()))
	if err != nil {
		log.Printf("Failed to write string to buffer: %v", err)
		return nil
	}

	writeSSHString(&buf, host)
	err = binary.Write(&buf, binary.BigEndian, uint32(originPort))
	if err != nil {
		log.Printf("Failed to write string to buffer: %v", err)
		return nil
	}

	return buf.Bytes()
}

func parseAddr(addr string) (string, uint16) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		log.Printf("Failed to parse origin address: %s from address %s", err.Error(), addr)
		return "0.0.0.0", uint16(0)
	}
	port, _ := strconv.Atoi(portStr)
	return host, uint16(port)
}

func writeSSHString(buffer *bytes.Buffer, str string) {
	err := binary.Write(buffer, binary.BigEndian, uint32(len(str)))
	if err != nil {
		log.Printf("Failed to write string to buffer: %v", err)
		return
	}
	buffer.WriteString(str)
}
