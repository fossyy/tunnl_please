package session

import (
	"bufio"
	"bytes"
	"context"
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
	if s.forwarder.Listener != nil {
		err := s.forwarder.Listener.Close()
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

	slug := s.forwarder.getSlug()
	if slug != "" {
		unregisterClient(slug)
	}

	if s.forwarder.TunnelType == TCP && s.forwarder.Listener != nil {
		err := portUtil.Manager.SetPortStatus(s.forwarder.ForwardedPort, false)
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
			req.Reply(true, nil)
		default:
			log.Println("Unknown request type:", req.Type)
			req.Reply(false, nil)
		}
	}
}

func (s *SSHSession) handleTCPIPForward(req *ssh.Request) {
	log.Println("Port forwarding request detected")

	reader := bytes.NewReader(req.Payload)

	addr, err := readSSHString(reader)
	if err != nil {
		log.Println("Failed to read address from payload:", err)
		req.Reply(false, nil)
		err := s.Close()
		if err != nil {
			log.Printf("failed to close session: %v", err)
		}
		return
	}

	var rawPortToBind uint32
	if err := binary.Read(reader, binary.BigEndian, &rawPortToBind); err != nil {
		log.Println("Failed to read port from payload:", err)
		s.interaction.SendMessage(fmt.Sprintf("Port %d is already in use or restricted. Please choose a different port. (02) \r\n", rawPortToBind))
		req.Reply(false, nil)
		err := s.Close()
		if err != nil {
			log.Printf("failed to close session: %v", err)
		}
		return
	}

	if rawPortToBind > 65535 {
		s.interaction.SendMessage(fmt.Sprintf("Port %d is larger then allowed port of 65535. (02)\r\n", rawPortToBind))
		req.Reply(false, nil)
		err := s.Close()
		if err != nil {
			log.Printf("failed to close session: %v", err)
		}
		return
	}

	portToBind := uint16(rawPortToBind)

	if isBlockedPort(portToBind) {
		s.interaction.SendMessage(fmt.Sprintf("Port %d is already in use or restricted. Please choose a different port. (02)\r\n", portToBind))
		req.Reply(false, nil)
		err := s.Close()
		if err != nil {
			log.Printf("failed to close session: %v", err)
		}
		return
	}

	s.interaction.SendMessage("\033[H\033[2J")
	s.lifecycle.Status = RUNNING
	go s.interaction.HandleUserInput()

	if portToBind == 80 || portToBind == 443 {
		s.handleHTTPForward(req, portToBind)
		return
	} else {
		if portToBind == 0 {
			unassign, success := portUtil.Manager.GetUnassignedPort()
			portToBind = unassign
			if !success {
				s.interaction.SendMessage(fmt.Sprintf("No available port\r\n", portToBind))
				req.Reply(false, nil)
				err := s.Close()
				if err != nil {
					log.Printf("failed to close session: %v", err)
				}
				return
			}
		} else if isUse, isExist := portUtil.Manager.GetPortStatus(portToBind); isExist || isUse {
			s.interaction.SendMessage(fmt.Sprintf("Port %d is already in use or restricted. Please choose a different port. (03)\r\n", portToBind))
			req.Reply(false, nil)
			err := s.Close()
			if err != nil {
				log.Printf("failed to close session: %v", err)
			}
			return
		}
		portUtil.Manager.SetPortStatus(portToBind, true)
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
	s.forwarder.TunnelType = HTTP
	s.forwarder.ForwardedPort = portToBind

	slug := generateUniqueSlug()
	if slug == "" {
		req.Reply(false, nil)
		return
	}

	s.forwarder.setSlug(slug)
	registerClient(slug, s)

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, uint32(80))
	log.Printf("HTTP forwarding approved on port: %d", 80)

	domain := utils.Getenv("domain")
	protocol := "http"
	if utils.Getenv("tls_enabled") == "true" {
		protocol = "https"
	}

	s.interaction.ShowWelcomeMessage()
	s.interaction.SendMessage(fmt.Sprintf("Forwarding your traffic to %s://%s.%s\r\n", protocol, slug, domain))
	req.Reply(true, buf.Bytes())
}

func (s *SSHSession) handleTCPForward(req *ssh.Request, addr string, portToBind uint16) {
	s.forwarder.TunnelType = TCP
	log.Printf("Requested forwarding on %s:%d", addr, portToBind)

	listener, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", portToBind))
	if err != nil {
		s.interaction.SendMessage(fmt.Sprintf("Port %d is already in use or restricted. Please choose a different port.\r\n", portToBind))
		req.Reply(false, nil)
		err := s.Close()
		if err != nil {
			log.Printf("failed to close session: %v", err)
		}
		return
	}
	s.forwarder.Listener = listener
	s.forwarder.ForwardedPort = portToBind
	s.interaction.ShowWelcomeMessage()
	s.interaction.SendMessage(fmt.Sprintf("Forwarding your traffic to %s://%s:%d \r\n", s.forwarder.TunnelType, utils.Getenv("domain"), s.forwarder.ForwardedPort))

	go s.acceptTCPConnections()

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, uint32(portToBind))
	log.Printf("TCP forwarding approved on port: %d", portToBind)
	req.Reply(true, buf.Bytes())
}

func (s *SSHSession) acceptTCPConnections() {
	for {
		conn, err := s.forwarder.Listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("Error accepting connection: %v", err)
			continue
		}

		go s.HandleForwardedConnection(UserConnection{
			Reader: nil,
			Writer: conn,
		}, s.Conn)
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
			s.interaction.SendMessage(fmt.Sprintf("\rLoading %s", frames[i]))
			i = (i + 1) % len(frames)
			if s.lifecycle.Status == RUNNING {
				s.interaction.SendMessage("\r\033[K")
				return
			}
		case <-timeout:
			s.interaction.SendMessage("\r\033[K")
			s.interaction.SendMessage("TCP/IP request not received in time.\r\nCheck your internet connection and confirm the server responds within 3000ms.\r\nEnsure you ran the correct command. For more details, visit https://tunnl.live.\r\n\r\n")
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

func (s *SSHSession) HandleForwardedConnection(conn UserConnection, sshConn *ssh.ServerConn) {
	defer conn.Writer.Close()

	log.Printf("Handling new forwarded connection from %s", conn.Writer.RemoteAddr())
	host, originPort := ParseAddr(conn.Writer.RemoteAddr().String())

	timestamp := time.Now().Format("02/Jan/2006 15:04:05")

	payload := createForwardedTCPIPPayload(host, uint16(originPort), s.forwarder.ForwardedPort)
	channel, reqs, err := sshConn.OpenChannel("forwarded-tcpip", payload)
	if err != nil {
		log.Printf("Failed to open forwarded-tcpip channel: %v", err)
		sendBadGatewayResponse(conn.Writer)
		return
	}
	defer channel.Close()

	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("Panic in request handler: %v", r)
			}
		}()
		for req := range reqs {
			req.Reply(false, nil)
		}
	}()

	if conn.Reader == nil {
		conn.Reader = bufio.NewReader(conn.Writer)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("Panic in reader copy: %v", r)
			}
			cancel()
		}()

		_, err := io.Copy(channel, conn.Reader)
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
			log.Printf("Error copying from conn.Reader to channel: %v", err)
		}
		cancel()
	}()

	reader := bufio.NewReader(channel)

	peekChan := make(chan error, 1)
	go func() {
		_, err := reader.Peek(1)
		peekChan <- err
	}()

	select {
	case err := <-peekChan:
		if err == io.EOF {
			s.interaction.SendMessage(fmt.Sprintf("\033[33m%s -> [%s] WARNING -- \"Could not forward request to the tunnel addr\"\033[0m\r\n", conn.Writer.RemoteAddr().String(), s.forwarder.TunnelType))
			sendBadGatewayResponse(conn.Writer)
			return
		}
		if err != nil {
			log.Printf("Error peeking channel data: %v", err)
			s.interaction.SendMessage(fmt.Sprintf("\033[33m%s -> [%s] WARNING -- \"Could not forward request to the tunnel addr\"\033[0m\r\n", conn.Writer.RemoteAddr().String(), s.forwarder.TunnelType))
			sendBadGatewayResponse(conn.Writer)
			return
		}
	case <-time.After(5 * time.Second):
		log.Printf("Timeout waiting for channel data from %s", conn.Writer.RemoteAddr())
		s.interaction.SendMessage(fmt.Sprintf("\033[33m%s -> [%s] WARNING -- \"Could not forward request to the tunnel addr\"\033[0m\r\n", conn.Writer.RemoteAddr().String(), s.forwarder.TunnelType))
		sendBadGatewayResponse(conn.Writer)
		return
	case <-ctx.Done():
		return
	}

	s.interaction.SendMessage(fmt.Sprintf("\033[32m%s -> [%s] TUNNEL ADDRESS -- \"%s\"\033[0m\r\n", conn.Writer.RemoteAddr().String(), s.forwarder.TunnelType, timestamp))

	_, err = io.Copy(conn.Writer, reader)
	if err != nil && !errors.Is(err, io.EOF) {
		log.Printf("Error copying from channel to conn.Writer: %v", err)
	}
}

func sendBadGatewayResponse(writer io.Writer) {
	response := "HTTP/1.1 502 Bad Gateway\r\n" +
		"Content-Length: 11\r\n" +
		"Content-Type: text/plain\r\n\r\n" +
		"Bad Gateway"
	io.Copy(writer, bytes.NewReader([]byte(response)))
}

func writeSSHString(buffer *bytes.Buffer, str string) {
	binary.Write(buffer, binary.BigEndian, uint32(len(str)))
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

func createForwardedTCPIPPayload(host string, originPort, port uint16) []byte {
	var buf bytes.Buffer

	writeSSHString(&buf, "localhost")
	binary.Write(&buf, binary.BigEndian, uint32(port))
	writeSSHString(&buf, host)
	binary.Write(&buf, binary.BigEndian, uint32(originPort))

	return buf.Bytes()
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
