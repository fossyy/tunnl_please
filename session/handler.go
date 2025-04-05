package session

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/context"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"time"
	"tunnel_pls/utils"
)

type UserConnection struct {
	Reader  io.Reader
	Writer  net.Conn
	Context context.Context
}

func (s *Session) handleGlobalRequest() {
	for {
		select {
		case req := <-s.GlobalRequest:
			if req == nil {
				return
			}
			if req.Type == "tcpip-forward" {
				s.handleTCPIPForward(req)
				continue
			} else {
				req.Reply(false, nil)
			}
		case <-s.Done:
			break
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
		return
	}

	var portToBind uint32

	if err := binary.Read(reader, binary.BigEndian, &portToBind); err != nil {
		log.Println("Failed to read port from payload:", err)
		req.Reply(false, nil)
		return
	}

	if portToBind == 80 || portToBind == 443 {
		s.TunnelType = HTTP
		s.ForwardedPort = uint16(portToBind)
		var slug string
		for {
			slug = utils.GenerateRandomString(32)
			if _, ok := Clients[slug]; ok {
				return
			}
			break
		}
		Clients[slug] = s
		s.Slug = slug
		buf := new(bytes.Buffer)
		binary.Write(buf, binary.BigEndian, uint32(80))
		log.Printf("Forwarding approved on port: %d", 80)
		//TODO: fix status checking later
		for s.Status != RUNNING {
			time.Sleep(500 * time.Millisecond)
		}

		if utils.Getenv("tls_enabled") == "true" {
			s.ConnChannels[0].Write([]byte(fmt.Sprintf("Forwarding your traffic to https://%s.%s \r\n", slug, utils.Getenv("domain"))))
		} else {
			s.ConnChannels[0].Write([]byte(fmt.Sprintf("Forwarding your traffic to http://%s.%s \r\n", slug, utils.Getenv("domain"))))
		}
		req.Reply(true, buf.Bytes())

	} else {
		s.TunnelType = TCP
		log.Printf("Requested forwarding on %s:%d", addr, portToBind)

		listener, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", portToBind))
		if err != nil {
			log.Printf("Failed to bind to port %d: %v", portToBind, err)
			req.Reply(false, nil)
			return
		}
		s.Listener = listener
		s.ConnChannels[0].Write([]byte(fmt.Sprintf("Forwarding your traffic to %s:%d \r\n", utils.Getenv("domain"), portToBind)))
		go func() {
			for {
				fmt.Println("jalan di bawah")
				conn, err := listener.Accept()
				if err != nil {
					if errors.Is(err, net.ErrClosed) {
						return
					}
					log.Printf("Error accepting connection: %v", err)
					continue
				}

				go s.HandleForwardedConnection(UserConnection{
					Reader:  nil,
					Writer:  conn,
					Context: context.Background(),
				}, s.Connection, portToBind)
			}
		}()

		buf := new(bytes.Buffer)
		binary.Write(buf, binary.BigEndian, uint32(portToBind))

		log.Printf("Forwarding approved on port: %d", portToBind)
		req.Reply(true, buf.Bytes())
	}

}

func showWelcomeMessage(connection ssh.Channel) {
	fmt.Println("jalan nih")
	asciiArt := []string{
		` _______                        ____        `,
		`|_   __|                   | | |  __ \| |    `,
		`   | |_    __  _   ___| | | |__) | |___ `,
		`   | | | | | '_ \| '_ \ /  \ | |  __/| / __|`,
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
	connection.Write([]byte("\r\n\r\n"))
	connection.Write([]byte("  ╔══════════════════════════════════════════════╗\r\n"))
	connection.Write([]byte("  ║            SUBDOMAIN EDITOR                  ║\r\n"))
	connection.Write([]byte("  ╠══════════════════════════════════════════════╣\r\n"))
	connection.Write([]byte("  ║                                              ║\r\n"))
	connection.Write([]byte("  ║  Current:  " + currentSlug + "." + utils.Getenv("domain") + strings.Repeat(" ", max(0, 30-len(currentSlug)-len(utils.Getenv("domain")))) + "║\r\n"))
	connection.Write([]byte("  ║                                              ║\r\n"))
	connection.Write([]byte("  ║  New:                                        ║\r\n"))
	connection.Write([]byte("  ║                                              ║\r\n"))
	connection.Write([]byte("  ╠══════════════════════════════════════════════╣\r\n"))
	connection.Write([]byte("  ║  [Enter] Save  |  [Esc] Cancel               ║\r\n"))
	connection.Write([]byte("  ╚══════════════════════════════════════════════╝\r\n\r\n"))
}

func (s *Session) HandleSessionChannel(newChannel ssh.NewChannel) {
	connection, requests, err := newChannel.Accept()
	s.ConnChannels = append(s.ConnChannels, connection)
	if err != nil {
		log.Printf("Could not accept channel: %s", err)
		return
	}
	go func() {
		var commandBuffer bytes.Buffer
		buf := make([]byte, 1)
		inSlugEditMode := false
		editSlug := s.Slug

		for {
			n, err := connection.Read(buf)
			if n > 0 {
				char := buf[0]

				if inSlugEditMode {
					if char == 13 {
						isValid := true
						if len(editSlug) < 3 || len(editSlug) > 20 {
							isValid = false
						} else {
							for _, c := range editSlug {
								if !((c >= 'a' && c <= 'z') ||
									(c >= '0' && c <= '9') ||
									c == '-') {
									isValid = false
									break
								}
							}
							if editSlug[0] == '-' || editSlug[len(editSlug)-1] == '-' {
								isValid = false
							}
						}

						connection.Write([]byte("\033[H\033[2J"))

						if isValid {
							oldSlug := s.Slug
							newSlug := editSlug

							client, ok := Clients[oldSlug]
							if !ok {
								connection.Write([]byte("\r\n\r\n❌ SERVER ERROR ❌\r\n\r\n"))
								connection.Write([]byte("Failed to update subdomain. You will be disconnected in 5 seconds.\r\n\r\n"))

								for i := 5; i > 0; i-- {
									connection.Write([]byte(fmt.Sprintf("Disconnecting in %d...\r\n", i)))
									time.Sleep(1 * time.Second)
								}

								s.Close()
								return
							}

							if _, exists := Clients[newSlug]; exists && newSlug != oldSlug {
								connection.Write([]byte("\r\n\r\n❌ SUBDOMAIN ALREADY IN USE ❌\r\n\r\n"))
								connection.Write([]byte("This subdomain is already taken. Please try another one.\r\n\r\n"))
								connection.Write([]byte("Press any key to continue...\r\n"))

								waitForKeyPress := true
								for waitForKeyPress {
									keyBuf := make([]byte, 1)
									_, err := connection.Read(keyBuf)
									if err == nil {
										waitForKeyPress = false
									}
								}

								connection.Write([]byte("\033[H\033[2J"))
								inSlugEditMode = true
								editSlug = oldSlug

								displaySlugEditor(connection, oldSlug)
								connection.Write([]byte("➤ " + editSlug + "." + utils.Getenv("domain")))
								continue
							}

							delete(Clients, oldSlug)
							client.Slug = newSlug
							//TODO: uneceserry channel
							client.SlugChannel <- true
							Clients[newSlug] = client

							connection.Write([]byte("\r\n\r\n✅ SUBDOMAIN UPDATED ✅\r\n\r\n"))
							connection.Write([]byte("Your new address is: " + newSlug + "." + utils.Getenv("domain") + "\r\n\r\n"))
							connection.Write([]byte("Press any key to continue...\r\n"))
						} else {
							connection.Write([]byte("\r\n\r\n❌ INVALID SUBDOMAIN ❌\r\n\r\n"))
							connection.Write([]byte("Use only lowercase letters, numbers, and hyphens.\r\n"))
							connection.Write([]byte("Length must be 3-20 characters and cannot start or end with a hyphen.\r\n\r\n"))
							connection.Write([]byte("Press any key to continue...\r\n"))
						}

						waitForKeyPress := true
						for waitForKeyPress {
							keyBuf := make([]byte, 1)
							_, err := connection.Read(keyBuf)
							if err == nil {
								waitForKeyPress = false
							}
						}

						connection.Write([]byte("\033[H\033[2J"))
						showWelcomeMessage(connection)
						if utils.Getenv("tls_enabled") == "true" {
							s.ConnChannels[0].Write([]byte(fmt.Sprintf("Forwarding your traffic to https://%s.%s \r\n", s.Slug, utils.Getenv("domain"))))
						} else {
							s.ConnChannels[0].Write([]byte(fmt.Sprintf("Forwarding your traffic to http://%s.%s \r\n", s.Slug, utils.Getenv("domain"))))
						}

						inSlugEditMode = false
						commandBuffer.Reset()
						continue
					} else if char == 27 {
						inSlugEditMode = false
						connection.Write([]byte("\033[H\033[2J"))
						connection.Write([]byte("\r\n\r\n⚠️ SUBDOMAIN EDIT CANCELLED ⚠️\r\n\r\n"))
						connection.Write([]byte("Press any key to continue...\r\n"))

						waitForKeyPress := true
						for waitForKeyPress {
							keyBuf := make([]byte, 1)
							_, err := connection.Read(keyBuf)
							if err == nil {
								waitForKeyPress = false
							}
						}

						connection.Write([]byte("\033[H\033[2J"))
						showWelcomeMessage(connection)

						commandBuffer.Reset()
						continue
					} else if char == 8 || char == 127 {
						if len(editSlug) > 0 {
							editSlug = editSlug[:len(editSlug)-1]
							connection.Write([]byte("\r\033[K"))
							connection.Write([]byte("➤ " + editSlug + "." + utils.Getenv("domain")))
						}
						continue
					} else if char >= 32 && char <= 126 {
						if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '-' {
							editSlug += string(char)
							connection.Write([]byte("\r\033[K"))
							connection.Write([]byte("➤ " + editSlug + "." + utils.Getenv("domain")))
						}
						continue
					}
					continue
				}

				connection.Write(buf[:n])

				if char == 8 || char == 127 {
					if commandBuffer.Len() > 0 {
						commandBuffer.Truncate(commandBuffer.Len() - 1)
						connection.Write([]byte("\b \b"))
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
						command := commandBuffer.String()
						fmt.Println("User entered command:", command, "<>")

						if command == "/bye" {
							fmt.Println("Closing connection...")
							s.Close()
							break
						} else if command == "/debug" {
							fmt.Println(Clients)
						} else if command == "/help" {
							connection.Write([]byte("\r\nAvailable commands: /bye, /help, /clear, /slug"))
						} else if command == "/clear" {
							connection.Write([]byte("\033[H\033[2J"))
						} else if command == "/slug" {
							if s.TunnelType != HTTP {
								connection.Write([]byte(fmt.Sprintf("%s cannot be edited", s.TunnelType)))
								continue
							}
							inSlugEditMode = true
							editSlug = s.Slug

							connection.Write([]byte("\033[H\033[2J"))

							connection.Write([]byte("\r\n\r\n"))
							connection.Write([]byte("  ╔══════════════════════════════════════════════╗\r\n"))
							connection.Write([]byte("  ║            SUBDOMAIN EDITOR                  ║\r\n"))
							connection.Write([]byte("  ╠══════════════════════════════════════════════╣\r\n"))
							connection.Write([]byte("  ║                                              ║\r\n"))
							connection.Write([]byte("  ║  Current:  " + s.Slug + "." + utils.Getenv("domain") + "║\r\n"))
							connection.Write([]byte("  ║                                              ║\r\n"))
							connection.Write([]byte("  ║  New:                                        ║\r\n"))
							connection.Write([]byte("  ║                                              ║\r\n"))
							connection.Write([]byte("  ╠══════════════════════════════════════════════╣\r\n"))
							connection.Write([]byte("  ║  [Enter] Save  |  [Esc] Cancel               ║\r\n"))
							connection.Write([]byte("  ╚══════════════════════════════════════════════╝\r\n\r\n"))

							connection.Write([]byte("➤ " + editSlug + "." + utils.Getenv("domain")))
						} else {
							connection.Write([]byte("\r\nUnknown command"))
						}

						commandBuffer.Reset()
						continue
					}

					commandBuffer.WriteByte(char)
					continue
				}
			}

			if err != nil {
				if err != io.EOF {
					log.Printf("Error reading from client: %s", err)
				}
				break
			}
		}
	}()

	go func() {
		connection.Write([]byte("\033[H\033[2J"))
		showWelcomeMessage(connection)
		s.Status = RUNNING

		go s.handleGlobalRequest()

		for req := range requests {
			switch req.Type {
			case "shell", "pty-req", "window-change":
				req.Reply(true, nil)
			default:
				fmt.Println("Unknown request type of : ", req.Type)
				req.Reply(false, nil)
			}
		}
	}()
}

func (s *Session) HandleForwardedConnection(conn UserConnection, sshConn *ssh.ServerConn, port uint32) {
	defer conn.Writer.Close()

	log.Printf("Handling new forwarded connection from %s", conn.Writer.RemoteAddr())
	host, originPort := ParseAddr(conn.Writer.RemoteAddr().String())
	s.ConnChannels[0].Write([]byte(fmt.Sprintf("\033[32m %s -> [%s] TUNNEL ADDRESS -- \"%s\" 	\r\n \033[0m", conn.Writer.RemoteAddr().String(), s.TunnelType, time.Now().Format("02/Jan/2006 15:04:05"))))

	payload := createForwardedTCPIPPayload(host, uint16(originPort), uint16(port))
	channel, reqs, err := sshConn.OpenChannel("forwarded-tcpip", payload)
	if err != nil {
		log.Printf("Failed to open forwarded-tcpip channel: %v", err)
		io.Copy(conn.Writer, bytes.NewReader([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 11\r\nContent-Type: text/plain\r\n\r\nBad Gateway")))
		return
	}
	defer channel.Close()

	go func() {
		select {
		case <-reqs:
			for req := range reqs {
				req.Reply(false, nil)
			}
		case <-conn.Context.Done():
			conn.Writer.Close()
			channel.Close()
			fmt.Println("cancel by timeout")
			return
		case <-s.SlugChannel:
			conn.Writer.Close()
			channel.Close()
			fmt.Println("cancel by slug")
			return
		}
	}()

	defer channel.Close()
	if conn.Reader == nil {
		conn.Reader = bufio.NewReader(conn.Writer)
	}

	go io.Copy(channel, conn.Reader)
	reader := bufio.NewReader(channel)
	_, err = reader.Peek(1)
	if err == io.EOF {
		s.ConnChannels[0].Write([]byte("Could not forward request to the tunnel addr 1\r\n"))
		return
	}

	io.Copy(conn.Writer, reader)
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
