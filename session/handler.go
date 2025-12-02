package session

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"time"
	portUtil "tunnel_pls/internal/port"

	"tunnel_pls/utils"

	"golang.org/x/crypto/ssh"
)

type SessionStatus string

var forbiddenSlug = []string{
	"ping",
}

type UserConnection struct {
	Reader io.Reader
	Writer net.Conn
}

var (
	clientsMutex sync.RWMutex
	Clients      = make(map[string]*SSHSession)
)

func registerClient(slug string, session *SSHSession) bool {
	clientsMutex.Lock()
	defer clientsMutex.Unlock()

	if _, exists := Clients[slug]; exists {
		return false
	}

	Clients[slug] = session
	return true
}

func unregisterClient(slug string) {
	clientsMutex.Lock()
	defer clientsMutex.Unlock()

	delete(Clients, slug)
}

func (s *SSHSession) Close() error {
	if s.Forwarder.Listener != nil {
		err := s.Forwarder.Listener.Close()
		if err != nil && !errors.Is(err, net.ErrClosed) {
			return err
		}
	}

	if s.channel != nil {
		err := s.channel.Close()
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
	}

	if s.Conn != nil {
		err := s.Conn.Close()
		if err != nil && !errors.Is(err, net.ErrClosed) {
			return err
		}
	}

	slug := s.Forwarder.getSlug()
	if slug != "" {
		unregisterClient(slug)
	}

	if s.Forwarder.TunnelType == TCP && s.Forwarder.Listener != nil {
		err := portUtil.Manager.SetPortStatus(s.Forwarder.ForwardedPort, false)
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *SSHSession) HandleGlobalRequest(GlobalRequest <-chan *ssh.Request) {
	for req := range GlobalRequest {
		switch req.Type {
		case "tcpip-forward":
			s.handleTCPIPForward(req)
			return
		case "shell", "pty-req", "window-change":
			err := req.Reply(true, nil)
			if err != nil {
				log.Println("Failed to reply to request:", err)
				return
			}
		default:
			log.Println("Unknown request type:", req.Type)
			err := req.Reply(false, nil)
			if err != nil {
				log.Println("Failed to reply to request:", err)
				return
			}
		}
	}
}

func (s *SSHSession) handleTCPIPForward(req *ssh.Request) {
	log.Println("Port forwarding request detected")

	reader := bytes.NewReader(req.Payload)

	addr, err := readSSHString(reader)
	if err != nil {
		log.Println("Failed to read address from payload:", err)
		err := req.Reply(false, nil)
		if err != nil {
			log.Println("Failed to reply to request:", err)
			return
		}
		err = s.Close()
		if err != nil {
			log.Printf("failed to close session: %v", err)
		}
		return
	}

	var rawPortToBind uint32
	if err := binary.Read(reader, binary.BigEndian, &rawPortToBind); err != nil {
		log.Println("Failed to read port from payload:", err)
		s.Interaction.SendMessage(fmt.Sprintf("Port %d is already in use or restricted. Please choose a different port. (02) \r\n", rawPortToBind))
		err := req.Reply(false, nil)
		if err != nil {
			log.Println("Failed to reply to request:", err)
			return
		}
		err = s.Close()
		if err != nil {
			log.Printf("failed to close session: %v", err)
		}
		return
	}

	if rawPortToBind > 65535 {
		s.Interaction.SendMessage(fmt.Sprintf("Port %d is larger then allowed port of 65535. (02)\r\n", rawPortToBind))
		err := req.Reply(false, nil)
		if err != nil {
			log.Println("Failed to reply to request:", err)
			return
		}
		err = s.Close()
		if err != nil {
			log.Printf("failed to close session: %v", err)
		}
		return
	}

	portToBind := uint16(rawPortToBind)

	if isBlockedPort(portToBind) {
		s.Interaction.SendMessage(fmt.Sprintf("Port %d is already in use or restricted. Please choose a different port. (02)\r\n", portToBind))
		err := req.Reply(false, nil)
		if err != nil {
			log.Println("Failed to reply to request:", err)
			return
		}
		err = s.Close()
		if err != nil {
			log.Printf("failed to close session: %v", err)
		}
		return
	}

	s.Interaction.SendMessage("\033[H\033[2J")
	s.Lifecycle.Status = RUNNING
	go s.Interaction.HandleUserInput()

	if portToBind == 80 || portToBind == 443 {
		s.handleHTTPForward(req, portToBind)
		return
	} else {
		if portToBind == 0 {
			unassign, success := portUtil.Manager.GetUnassignedPort()
			portToBind = unassign
			if !success {
				s.Interaction.SendMessage(fmt.Sprintf("No available port\r\n", portToBind))
				err := req.Reply(false, nil)
				if err != nil {
					log.Println("Failed to reply to request:", err)
					return
				}
				err = s.Close()
				if err != nil {
					log.Printf("failed to close session: %v", err)
				}
				return
			}
		} else if isUse, isExist := portUtil.Manager.GetPortStatus(portToBind); isExist && isUse {
			s.Interaction.SendMessage(fmt.Sprintf("Port %d is already in use or restricted. Please choose a different port. (03)\r\n", portToBind))
			err := req.Reply(false, nil)
			if err != nil {
				log.Println("Failed to reply to request:", err)
				return
			}
			err = s.Close()
			if err != nil {
				log.Printf("failed to close session: %v", err)
			}
			return
		}
		err := portUtil.Manager.SetPortStatus(portToBind, true)
		if err != nil {
			log.Println("Failed to set port status:", err)
			return
		}
	}
	s.handleTCPForward(req, addr, portToBind)
}

var blockedReservedPorts = []uint16{1080, 1433, 1521, 1900, 2049, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9000, 9200, 27017}

func isBlockedPort(port uint16) bool {
	if port == 80 || port == 443 {
		return false
	}
	if port < 1024 && port != 0 {
		return true
	}
	for _, p := range blockedReservedPorts {
		if p == port {
			return true
		}
	}
	return false
}

func (s *SSHSession) handleHTTPForward(req *ssh.Request, portToBind uint16) {
	s.Forwarder.TunnelType = HTTP
	s.Forwarder.ForwardedPort = portToBind

	slug := generateUniqueSlug()
	if slug == "" {
		err := req.Reply(false, nil)
		if err != nil {
			log.Println("Failed to reply to request:", err)
			return
		}
		return
	}

	s.Forwarder.setSlug(slug)
	registerClient(slug, s)

	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, uint32(80))
	if err != nil {
		log.Println("Failed to reply to request:", err)
		return
	}
	log.Printf("HTTP forwarding approved on port: %d", 80)

	domain := utils.Getenv("domain")
	protocol := "http"
	if utils.Getenv("tls_enabled") == "true" {
		protocol = "https"
	}

	s.Interaction.ShowWelcomeMessage()
	s.Interaction.SendMessage(fmt.Sprintf("Forwarding your traffic to %s://%s.%s\r\n", protocol, slug, domain))
	err = req.Reply(true, buf.Bytes())
	if err != nil {
		log.Println("Failed to reply to request:", err)
		return
	}
}

func (s *SSHSession) handleTCPForward(req *ssh.Request, addr string, portToBind uint16) {
	s.Forwarder.TunnelType = TCP
	log.Printf("Requested forwarding on %s:%d", addr, portToBind)

	listener, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", portToBind))
	if err != nil {
		s.Interaction.SendMessage(fmt.Sprintf("Port %d is already in use or restricted. Please choose a different port.\r\n", portToBind))
		err := req.Reply(false, nil)
		if err != nil {
			log.Println("Failed to reply to request:", err)
			return
		}
		err = s.Close()
		if err != nil {
			log.Printf("failed to close session: %v", err)
		}
		return
	}
	s.Forwarder.Listener = listener
	s.Forwarder.ForwardedPort = portToBind
	s.Interaction.ShowWelcomeMessage()
	s.Interaction.SendMessage(fmt.Sprintf("Forwarding your traffic to %s://%s:%d \r\n", s.Forwarder.TunnelType, utils.Getenv("domain"), s.Forwarder.ForwardedPort))

	go s.acceptTCPConnections()

	buf := new(bytes.Buffer)
	err = binary.Write(buf, binary.BigEndian, uint32(portToBind))
	if err != nil {
		log.Println("Failed to reply to request:", err)
		return
	}
	log.Printf("TCP forwarding approved on port: %d", portToBind)
	err = req.Reply(true, buf.Bytes())
	if err != nil {
		log.Println("Failed to reply to request:", err)
		return
	}
}

func (s *SSHSession) acceptTCPConnections() {
	for {
		conn, err := s.Forwarder.Listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("Error accepting connection: %v", err)
			continue
		}
		originHost, originPort := ParseAddr(conn.RemoteAddr().String())
		payload := createForwardedTCPIPPayload(originHost, uint16(originPort), s.Forwarder.GetForwardedPort())
		channel, reqs, err := s.Conn.OpenChannel("forwarded-tcpip", payload)
		if err != nil {
			log.Printf("Failed to open forwarded-tcpip channel: %v", err)
			return
		}
		defer func(channel ssh.Channel) {
			err := channel.Close()
			if err != nil {
				log.Println("Failed to close connection:", err)
			}
		}(channel)

		go func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("Panic in request handler: %v", r)
				}
			}()
			for req := range reqs {
				err := req.Reply(false, nil)
				if err != nil {
					log.Printf("Failed to reply to request: %v", err)
					return
				}
			}
		}()
		go s.HandleForwardedConnection(conn, channel, conn.RemoteAddr())
	}
}

func generateUniqueSlug() string {
	maxAttempts := 5

	for i := 0; i < maxAttempts; i++ {
		slug := utils.GenerateRandomString(20)

		clientsMutex.RLock()
		_, exists := Clients[slug]
		clientsMutex.RUnlock()

		if !exists {
			return slug
		}
	}

	log.Println("Failed to generate unique slug after multiple attempts")
	return ""
}

func (s *SSHSession) waitForRunningStatus() {
	timeout := time.After(3 * time.Second)
	ticker := time.NewTicker(150 * time.Millisecond)
	defer ticker.Stop()
	frames := []string{"-", "\\", "|", "/"}
	i := 0
	for {
		select {
		case <-ticker.C:
			s.Interaction.SendMessage(fmt.Sprintf("\rLoading %s", frames[i]))
			i = (i + 1) % len(frames)
			if s.Lifecycle.Status == RUNNING {
				s.Interaction.SendMessage("\r\033[K")
				return
			}
		case <-timeout:
			s.Interaction.SendMessage("\r\033[K")
			s.Interaction.SendMessage("TCP/IP request not received in time.\r\nCheck your internet connection and confirm the server responds within 3000ms.\r\nEnsure you ran the correct command. For more details, visit https://tunnl.live.\r\n\r\n")
			err := s.Close()
			if err != nil {
				log.Printf("failed to close session: %v", err)
			}
			log.Println("Timeout waiting for session to start running")
			return
		}
	}
}

func isForbiddenSlug(slug string) bool {
	for _, s := range forbiddenSlug {
		if slug == s {
			return true
		}
	}
	return false
}

func isValidSlug(slug string) bool {
	if len(slug) < 3 || len(slug) > 20 {
		return false
	}

	if slug[0] == '-' || slug[len(slug)-1] == '-' {
		return false
	}

	for _, c := range slug {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
			return false
		}
	}

	return true
}

func waitForKeyPress(connection ssh.Channel) {
	keyBuf := make([]byte, 1)
	for {
		_, err := connection.Read(keyBuf)
		if err == nil {
			break
		}
	}
}

func (s *SSHSession) HandleForwardedConnection(dst io.ReadWriter, src ssh.Channel, remoteAddr net.Addr) {
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

func readSSHString(reader *bytes.Reader) (string, error) {
	var length uint32
	if err := binary.Read(reader, binary.BigEndian, &length); err != nil {
		return "", err
	}
	strBytes := make([]byte, length)
	if _, err := reader.Read(strBytes); err != nil {
		return "", err
	}
	return string(strBytes), nil
}

func createForwardedTCPIPPayload(host string, originPort, port uint16) []byte {
	var buf bytes.Buffer

	writeSSHString(&buf, "localhost")
	err := binary.Write(&buf, binary.BigEndian, uint32(port))
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

func writeSSHString(buffer *bytes.Buffer, str string) {
	err := binary.Write(buffer, binary.BigEndian, uint32(len(str)))
	if err != nil {
		log.Printf("Failed to write string to buffer: %v", err)
		return
	}
	buffer.WriteString(str)
}

func ParseAddr(addr string) (string, uint32) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		log.Printf("Failed to parse origin address: %s from address %s", err.Error(), addr)
		return "0.0.0.0", uint32(0)
	}
	port, _ := strconv.Atoi(portStr)
	return host, uint32(port)
}
