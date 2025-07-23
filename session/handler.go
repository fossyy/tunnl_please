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
	"strings"
	"sync"
	"time"
	portUtil "tunnel_pls/internal/port"

	"golang.org/x/crypto/ssh"
	"tunnel_pls/utils"
)

type SessionStatus string

const (
	INITIALIZING SessionStatus = "INITIALIZING"
	RUNNING      SessionStatus = "RUNNING"
	SETUP        SessionStatus = "SETUP"
)

type UserConnection struct {
	Reader io.Reader
	Writer net.Conn
}

var (
	clientsMutex sync.RWMutex
	Clients      = make(map[string]*Session)
)

func registerClient(slug string, session *Session) bool {
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

func updateClientSlug(oldSlug, newSlug string) bool {
	clientsMutex.Lock()
	defer clientsMutex.Unlock()

	if _, exists := Clients[newSlug]; exists && newSlug != oldSlug {
		return false
	}

	client, ok := Clients[oldSlug]
	if !ok {
		return false
	}

	delete(Clients, oldSlug)
	client.Slug = newSlug
	Clients[newSlug] = client
	return true
}

func (s *Session) safeClose() {
	s.once.Do(func() {
		close(s.ChannelChan)
		close(s.Done)
	})
}

func (s *Session) Close() error {
	if s.Listener != nil {
		err := s.Listener.Close()
		if err != nil && !errors.Is(err, net.ErrClosed) {
			fmt.Println("1")
			return err
		}
	}

	if s.ConnChannel != nil {
		err := s.ConnChannel.Close()
		if err != nil && !errors.Is(err, io.EOF) {
			fmt.Println("2")
			return err
		}
	}

	if s.Connection != nil {
		err := s.Connection.Close()
		if err != nil && !errors.Is(err, net.ErrClosed) {
			fmt.Println("3")

			return err
		}
	}

	if s.Slug != "" {
		unregisterClient(s.Slug)
	}

	if s.TunnelType == TCP {
		err := portUtil.Manager.SetPortStatus(s.ForwardedPort, false)
		if err != nil {
			fmt.Println("4")
			return err
		}
	}

	s.safeClose()
	return nil
}

func (s *Session) HandleGlobalRequest(GlobalRequest <-chan *ssh.Request) {
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

func (s *Session) handleTCPIPForward(req *ssh.Request) {
	log.Println("Port forwarding request detected")

	reader := bytes.NewReader(req.Payload)

	addr, err := readSSHString(reader)
	if err != nil {
		log.Println("Failed to read address from payload:", err)
		req.Reply(false, nil)
		s.Close()
		return
	}

	var rawPortToBind uint32
	if err := binary.Read(reader, binary.BigEndian, &rawPortToBind); err != nil {
		log.Println("Failed to read port from payload:", err)
		s.sendMessage(fmt.Sprintf("Port %d is already in use or restricted. Please choose a different port. (02) \r\n", rawPortToBind))
		req.Reply(false, nil)
		s.Close()
		return
	}

	if rawPortToBind > 65535 {
		s.sendMessage(fmt.Sprintf("Port %d is larger then allowed port of 65535. (02)\r\n", rawPortToBind))
		req.Reply(false, nil)
		s.Close()
		return
	}

	portToBind := uint16(rawPortToBind)

	if isBlockedPort(portToBind) {
		s.sendMessage(fmt.Sprintf("Port %d is already in use or restricted. Please choose a different port. (02)\r\n", portToBind))
		req.Reply(false, nil)
		s.Close()
		return
	}

	s.sendMessage("\033[H\033[2J")

	showWelcomeMessage(s.ConnChannel)
	s.Status = RUNNING
	go s.handleUserInput()

	if portToBind == 80 || portToBind == 443 {
		s.handleHTTPForward(req, portToBind)
		return
	} else {
		if portToBind == 0 {
			unassign, success := portUtil.Manager.GetUnassignedPort()
			portToBind = unassign
			if !success {
				s.sendMessage(fmt.Sprintf("No available port\r\n", portToBind))
				req.Reply(false, nil)
				s.Close()
				return
			}
		} else if isUse, isExist := portUtil.Manager.GetPortStatus(portToBind); !isExist || isUse {
			s.sendMessage(fmt.Sprintf("Port %d is already in use or restricted. Please choose a different port. (03)\r\n", portToBind))
			req.Reply(false, nil)
			s.Close()
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

func (s *Session) handleHTTPForward(req *ssh.Request, portToBind uint16) {
	s.TunnelType = HTTP
	s.ForwardedPort = uint16(portToBind)

	slug := s.generateUniqueSlug()
	if slug == "" {
		req.Reply(false, nil)
		return
	}

	s.Slug = slug
	registerClient(slug, s)

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, uint32(80))
	log.Printf("HTTP forwarding approved on port: %d", 80)

	s.waitForRunningStatus()

	domain := utils.Getenv("domain")
	protocol := "http"
	if utils.Getenv("tls_enabled") == "true" {
		protocol = "https"
	}

	s.sendMessage(fmt.Sprintf("Forwarding your traffic to %s://%s.%s\r\n", protocol, slug, domain))
	req.Reply(true, buf.Bytes())
}

func (s *Session) handleTCPForward(req *ssh.Request, addr string, portToBind uint16) {
	s.TunnelType = TCP
	log.Printf("Requested forwarding on %s:%d", addr, portToBind)

	listener, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", portToBind))
	if err != nil {
		s.sendMessage(fmt.Sprintf("Port %d is already in use or restricted. Please choose a different port.\r\n", portToBind))
		req.Reply(false, nil)
		s.Close()
		return
	}
	s.Listener = listener
	s.ForwardedPort = uint16(portToBind)
	s.sendMessage(fmt.Sprintf("Forwarding your traffic to %s://%s:%d \r\n", s.TunnelType, utils.Getenv("domain"), s.ForwardedPort))

	go s.acceptTCPConnections()

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, uint32(portToBind))
	log.Printf("TCP forwarding approved on port: %d", portToBind)
	req.Reply(true, buf.Bytes())
}

func (s *Session) acceptTCPConnections() {
	for {
		conn, err := s.Listener.Accept()
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
		}, s.Connection)
	}
}

func (s *Session) generateUniqueSlug() string {
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

func (s *Session) waitForRunningStatus() {
	timeout := time.After(10 * time.Second)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if s.Status == RUNNING {
				return
			}
		case <-timeout:
			log.Println("Timeout waiting for session to start running")
			return
		}
	}
}

func (s *Session) sendMessage(message string) {
	if s.ConnChannel != nil {
		s.ConnChannel.Write([]byte(message))
	}
}

func (s *Session) handleUserInput() {
	var commandBuffer bytes.Buffer
	buf := make([]byte, 1)
	inSlugEditMode := false
	editSlug := s.Slug

	for {
		n, err := s.ConnChannel.Read(buf)
		if err != nil {
			if err != io.EOF {
				log.Printf("Error reading from client: %s", err)
			}
			break
		}

		if n > 0 {
			char := buf[0]

			if inSlugEditMode {
				s.handleSlugEditMode(s.ConnChannel, &inSlugEditMode, &editSlug, char, &commandBuffer)
				continue
			}

			s.ConnChannel.Write(buf[:n])

			if char == 8 || char == 127 {
				if commandBuffer.Len() > 0 {
					commandBuffer.Truncate(commandBuffer.Len() - 1)
					s.ConnChannel.Write([]byte("\b \b"))
				}
				continue
			}

			if char == '/' {
				commandBuffer.Reset()
				commandBuffer.WriteByte(char)
				continue
			}

			if commandBuffer.Len() > 0 {
				if char == 13 {
					s.handleCommand(s.ConnChannel, commandBuffer.String(), &inSlugEditMode, &editSlug, &commandBuffer)
					continue
				}
				commandBuffer.WriteByte(char)
			}
		}
	}
}

func (s *Session) handleSlugEditMode(connection ssh.Channel, inSlugEditMode *bool, editSlug *string, char byte, commandBuffer *bytes.Buffer) {
	if char == 13 {
		s.handleSlugSave(connection, inSlugEditMode, editSlug, commandBuffer)
	} else if char == 27 {
		s.handleSlugCancel(connection, inSlugEditMode, commandBuffer)
	} else if char == 8 || char == 127 {
		if len(*editSlug) > 0 {
			*editSlug = (*editSlug)[:len(*editSlug)-1]
			connection.Write([]byte("\r\033[K"))
			connection.Write([]byte("➤ " + *editSlug + "." + utils.Getenv("domain")))
		}
	} else if char >= 32 && char <= 126 {
		if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '-' {
			*editSlug += string(char)
			connection.Write([]byte("\r\033[K"))
			connection.Write([]byte("➤ " + *editSlug + "." + utils.Getenv("domain")))
		}
	}
}

func (s *Session) handleSlugSave(connection ssh.Channel, inSlugEditMode *bool, editSlug *string, commandBuffer *bytes.Buffer) {
	isValid := isValidSlug(*editSlug)

	connection.Write([]byte("\033[H\033[2J"))

	if isValid {
		oldSlug := s.Slug
		newSlug := *editSlug

		if !updateClientSlug(oldSlug, newSlug) {
			handleSlugUpdateError(connection, s)
			return
		}

		connection.Write([]byte("\r\n\r\n✅ SUBDOMAIN UPDATED ✅\r\n\r\n"))
		connection.Write([]byte("Your new address is: " + newSlug + "." + utils.Getenv("domain") + "\r\n\r\n"))
		connection.Write([]byte("Press any key to continue...\r\n"))
	} else {
		connection.Write([]byte("\r\n\r\n❌ INVALID SUBDOMAIN ❌\r\n\r\n"))
		connection.Write([]byte("Use only lowercase letters, numbers, and hyphens.\r\n"))
		connection.Write([]byte("Length must be 3-20 characters and cannot start or end with a hyphen.\r\n\r\n"))
		connection.Write([]byte("Press any key to continue...\r\n"))
	}

	waitForKeyPress(connection)

	connection.Write([]byte("\033[H\033[2J"))
	showWelcomeMessage(connection)

	domain := utils.Getenv("domain")
	protocol := "http"
	if utils.Getenv("tls_enabled") == "true" {
		protocol = "https"
	}
	connection.Write([]byte(fmt.Sprintf("Forwarding your traffic to %s://%s.%s \r\n", protocol, s.Slug, domain)))

	*inSlugEditMode = false
	commandBuffer.Reset()
}

func (s *Session) handleSlugCancel(connection ssh.Channel, inSlugEditMode *bool, commandBuffer *bytes.Buffer) {
	*inSlugEditMode = false
	connection.Write([]byte("\033[H\033[2J"))
	connection.Write([]byte("\r\n\r\n⚠️ SUBDOMAIN EDIT CANCELLED ⚠️\r\n\r\n"))
	connection.Write([]byte("Press any key to continue...\r\n"))

	waitForKeyPress(connection)

	connection.Write([]byte("\033[H\033[2J"))
	showWelcomeMessage(connection)

	commandBuffer.Reset()
}

func handleSlugUpdateError(connection ssh.Channel, s *Session) {
	connection.Write([]byte("\r\n\r\n❌ SERVER ERROR ❌\r\n\r\n"))
	connection.Write([]byte("Failed to update subdomain. You will be disconnected in 5 seconds.\r\n\r\n"))

	for i := 5; i > 0; i-- {
		connection.Write([]byte(fmt.Sprintf("Disconnecting in %d...\r\n", i)))
		time.Sleep(1 * time.Second)
	}

	s.Close()
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

func (s *Session) handleCommand(connection ssh.Channel, command string, inSlugEditMode *bool, editSlug *string, commandBuffer *bytes.Buffer) {
	switch command {
	case "/bye":
		connection.Write([]byte("\r\nClosing connection..."))
		s.Close()
	case "/debug":
		log.Println("Client registry:", Clients)
	case "/help":
		connection.Write([]byte("\r\nAvailable commands: /bye, /help, /clear, /slug"))
	case "/clear":
		connection.Write([]byte("\033[H\033[2J"))
		showWelcomeMessage(s.ConnChannel)
		domain := utils.Getenv("domain")
		if s.TunnelType == HTTP {
			protocol := "http"
			if utils.Getenv("tls_enabled") == "true" {
				protocol = "https"
			}
			s.sendMessage(fmt.Sprintf("Forwarding your traffic to %s://%s.%s \r\n", protocol, s.Slug, domain))
		} else {
			s.sendMessage(fmt.Sprintf("Forwarding your traffic to %s://%s:%d \r\n", s.TunnelType, domain, s.ForwardedPort))
		}

	case "/slug":
		if s.TunnelType != HTTP {
			connection.Write([]byte(fmt.Sprintf("\r\n%s tunnels cannot have custom subdomains", s.TunnelType)))
		} else {
			*inSlugEditMode = true
			*editSlug = s.Slug
			connection.Write([]byte("\033[H\033[2J"))
			displaySlugEditor(connection, s.Slug)
			connection.Write([]byte("➤ " + *editSlug + "." + utils.Getenv("domain")))
		}
	default:
		connection.Write([]byte("\r\nUnknown command"))
	}

	commandBuffer.Reset()
}

func (s *Session) HandleForwardedConnection(conn UserConnection, sshConn *ssh.ServerConn) {
	defer conn.Writer.Close()

	log.Printf("Handling new forwarded connection from %s", conn.Writer.RemoteAddr())
	host, originPort := ParseAddr(conn.Writer.RemoteAddr().String())

	timestamp := time.Now().Format("02/Jan/2006 15:04:05")

	payload := createForwardedTCPIPPayload(host, uint16(originPort), s.ForwardedPort)
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
			s.sendMessage(fmt.Sprintf("\033[33m%s -> [%s] WARNING -- \"Could not forward request to the tunnel addr\"\033[0m\r\n", conn.Writer.RemoteAddr().String(), s.TunnelType))
			sendBadGatewayResponse(conn.Writer)
			return
		}
		if err != nil {
			log.Printf("Error peeking channel data: %v", err)
			s.sendMessage(fmt.Sprintf("\033[33m%s -> [%s] WARNING -- \"Could not forward request to the tunnel addr\"\033[0m\r\n", conn.Writer.RemoteAddr().String(), s.TunnelType))
			sendBadGatewayResponse(conn.Writer)
			return
		}
	case <-time.After(5 * time.Second):
		log.Printf("Timeout waiting for channel data from %s", conn.Writer.RemoteAddr())
		s.sendMessage(fmt.Sprintf("\033[33m%s -> [%s] WARNING -- \"Could not forward request to the tunnel addr\"\033[0m\r\n", conn.Writer.RemoteAddr().String(), s.TunnelType))
		sendBadGatewayResponse(conn.Writer)
		return
	case <-ctx.Done():
		return
	}

	s.sendMessage(fmt.Sprintf("\033[32m%s -> [%s] TUNNEL ADDRESS -- \"%s\"\033[0m\r\n", conn.Writer.RemoteAddr().String(), s.TunnelType, timestamp))

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

func showWelcomeMessage(connection ssh.Channel) {
	asciiArt := []string{
		` _______                     _   _____  _      `,
		`|__   __|                   | | |  __ \| |    `,
		`   | |_   _ _ __  _ __   ___| | | |__) | |___ `,
		`   | | | | | '_ \| '_ \ / _ \ | |  ___/| / __|`,
		`   | | |_| | | | | | | |  __/ | | |    | \__ \`,
		`   |_|\__,_|_| |_|_| |_|\___|_| |_|    |_|___/`,
		``,
		`       "Tunnel Pls" - Project by Bagas`,
		`           https://fossy.my.id`,
		``,
		`        Welcome to Tunnel! Available commands:`,
		`        - '/bye'   : Exit the tunnel`,
		`        - '/help'  : Show this help message`,
		`        - '/clear' : Clear the current line`,
		`        - '/slug'  : Set custom subdomain`,
	}

	for _, line := range asciiArt {
		connection.Write([]byte("\r\n" + line))
	}
	connection.Write([]byte("\r\n\r\n"))
}

func displaySlugEditor(connection ssh.Channel, currentSlug string) {
	domain := utils.Getenv("domain")
	fullDomain := currentSlug + "." + domain

	const paddingRight = 4

	contentLine := "  ║  Current:  " + fullDomain
	boxWidth := len(contentLine) + paddingRight + 1
	if boxWidth < 50 {
		boxWidth = 50
	}

	topBorder := "  ╔" + strings.Repeat("═", boxWidth-4) + "╗\r\n"
	title := centerText("SUBDOMAIN EDITOR", boxWidth-4)
	header := "  ║" + title + "║\r\n"
	midBorder := "  ╠" + strings.Repeat("═", boxWidth-4) + "╣\r\n"
	emptyLine := "  ║" + strings.Repeat(" ", boxWidth-4) + "║\r\n"

	currentLineContent := fmt.Sprintf("  ║  Current:  %s", fullDomain)
	currentLine := currentLineContent + strings.Repeat(" ", boxWidth-len(currentLineContent)+1) + "║\r\n"

	newLine := "  ║  New:" + strings.Repeat(" ", boxWidth-10) + "║\r\n"
	saveCancel := "  ║  [Enter] Save  |  [Esc] Cancel" + strings.Repeat(" ", boxWidth-35) + "║\r\n"
	bottomBorder := "  ╚" + strings.Repeat("═", boxWidth-4) + "╝\r\n"

	connection.Write([]byte("\r\n\r\n"))
	connection.Write([]byte(topBorder))
	connection.Write([]byte(header))
	connection.Write([]byte(midBorder))
	connection.Write([]byte(emptyLine))
	connection.Write([]byte(currentLine))
	connection.Write([]byte(emptyLine))
	connection.Write([]byte(newLine))
	connection.Write([]byte(emptyLine))
	connection.Write([]byte(midBorder))
	connection.Write([]byte(saveCancel))
	connection.Write([]byte(bottomBorder))
	connection.Write([]byte("\r\n\r\n"))
}

func centerText(text string, width int) string {
	padding := (width - len(text)) / 2
	if padding < 0 {
		padding = 0
	}
	return strings.Repeat(" ", padding) + text + strings.Repeat(" ", width-len(text)-padding)
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
