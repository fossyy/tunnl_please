package session

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	portUtil "tunnel_pls/internal/port"
	"tunnel_pls/types"

	"tunnel_pls/utils"

	"golang.org/x/crypto/ssh"
)

var blockedReservedPorts = []uint16{1080, 1433, 1521, 1900, 2049, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9000, 9200, 27017}

func (s *SSHSession) HandleGlobalRequest(GlobalRequest <-chan *ssh.Request) {
	for req := range GlobalRequest {
		switch req.Type {
		case "tcpip-forward":
			s.HandleTCPIPForward(req)
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

func (s *SSHSession) HandleTCPIPForward(req *ssh.Request) {
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
		err = s.Lifecycle.Close()
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
		err = s.Lifecycle.Close()
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
		err = s.Lifecycle.Close()
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
		err = s.Lifecycle.Close()
		if err != nil {
			log.Printf("failed to close session: %v", err)
		}
		return
	}

	s.Interaction.SendMessage("\033[H\033[2J")
	s.Lifecycle.SetStatus(types.RUNNING)
	go s.Interaction.HandleUserInput()

	if portToBind == 80 || portToBind == 443 {
		s.HandleHTTPForward(req, portToBind)
		return
	} else {
		if portToBind == 0 {
			unassign, success := portUtil.Manager.GetUnassignedPort()
			portToBind = unassign
			if !success {
				s.Interaction.SendMessage("No available port\r\n")
				err := req.Reply(false, nil)
				if err != nil {
					log.Println("Failed to reply to request:", err)
					return
				}
				err = s.Lifecycle.Close()
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
			err = s.Lifecycle.Close()
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
	s.HandleTCPForward(req, addr, portToBind)
}

func (s *SSHSession) HandleHTTPForward(req *ssh.Request, portToBind uint16) {
	s.Forwarder.SetType(types.HTTP)
	s.Forwarder.SetForwardedPort(portToBind)

	slug := generateUniqueSlug()
	if slug == "" {
		err := req.Reply(false, nil)
		if err != nil {
			log.Println("Failed to reply to request:", err)
			return
		}
		return
	}

	s.SlugManager.Set(slug)
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

func (s *SSHSession) HandleTCPForward(req *ssh.Request, addr string, portToBind uint16) {
	s.Forwarder.SetType(types.TCP)
	log.Printf("Requested forwarding on %s:%d", addr, portToBind)

	listener, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", portToBind))
	if err != nil {
		s.Interaction.SendMessage(fmt.Sprintf("Port %d is already in use or restricted. Please choose a different port.\r\n", portToBind))
		err := req.Reply(false, nil)
		if err != nil {
			log.Println("Failed to reply to request:", err)
			return
		}
		err = s.Lifecycle.Close()
		if err != nil {
			log.Printf("failed to close session: %v", err)
		}
		return
	}
	s.Forwarder.SetListener(listener)
	s.Forwarder.SetForwardedPort(portToBind)
	s.Interaction.ShowWelcomeMessage()
	s.Interaction.SendMessage(fmt.Sprintf("Forwarding your traffic to tcp://%s:%d \r\n", utils.Getenv("domain"), s.Forwarder.GetForwardedPort()))

	go s.Forwarder.AcceptTCPConnections()

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
