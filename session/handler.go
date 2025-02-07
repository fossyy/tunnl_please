package session

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"
	"log"
	"net"
	"strconv"
	"time"
	"tunnel_pls/proto"
	"tunnel_pls/utils"
)

func (s *Session) handleGlobalRequest() {
	for {
		select {
		case req := <-s.GlobalRequest:
			if req == nil {
				return
			}
			if req.Type == "tcpip-forward" {
				log.Println("Port forwarding request detected")

				reader := bytes.NewReader(req.Payload)

				addr, err := readSSHString(reader)
				if err != nil {
					log.Println("Failed to read address from payload:", err)
					req.Reply(false, nil)
					continue
				}

				var portToBind uint32

				if err := binary.Read(reader, binary.BigEndian, &portToBind); err != nil {
					log.Println("Failed to read port from payload:", err)
					req.Reply(false, nil)
					continue
				}

				if portToBind == 80 || portToBind == 443 {
					s.TunnelType = HTTP
					var slug string
					for {
						slug = utils.GenerateRandomString(32)
						if _, ok := Clients[slug]; ok {
							continue
						}
						break
					}
					Clients[slug] = s
					buf := new(bytes.Buffer)
					binary.Write(buf, binary.BigEndian, uint32(portToBind))
					log.Printf("Forwarding approved on port: %d", portToBind)
					s.ConnChannels[0].Write([]byte(fmt.Sprintf("Forwarding your traffic to http://%s.tunnl.live \r\n", slug)))
					req.Reply(true, buf.Bytes())
				} else {
					s.TunnelType = TCP
					log.Printf("Requested forwarding on %s:%d", addr, portToBind)

					listener, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", portToBind))
					if err != nil {
						log.Printf("Failed to bind to port %d: %v", portToBind, err)
						req.Reply(false, nil)
						continue
					}
					s.Listener = listener
					s.ConnChannels[0].Write([]byte(fmt.Sprintf("Forwarding your traffic to tunnl.live:%d \r\n", portToBind)))
					go func() {
						for {
							conn, err := listener.Accept()
							if err != nil {
								if errors.Is(err, net.ErrClosed) {
									return
								}
								log.Printf("Error accepting connection: %v", err)
								continue
							}

							go s.HandleForwardedConnection(conn, s.Connection, portToBind)
						}
					}()

					buf := new(bytes.Buffer)
					binary.Write(buf, binary.BigEndian, uint32(portToBind))

					log.Printf("Forwarding approved on port: %d", portToBind)
					req.Reply(true, buf.Bytes())
				}

			} else {
				req.Reply(false, nil)
			}
		case <-s.Done:
			break
		}
	}
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
		for {
			n, err := connection.Read(buf)
			if n > 0 {
				char := buf[0]
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
						} else if command == "/help" {
							connection.Write([]byte("Available commands: /bye, /help, /clear"))

						} else if command == "/clear" {
							connection.Write([]byte("\033[H\033[2J"))
						} else {
							connection.Write([]byte("Unknown command"))
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
		}

		connection.Write([]byte("\033[H\033[2J"))

		for _, line := range asciiArt {
			connection.Write([]byte("\r\n" + line))
		}

		connection.Write([]byte("\r\n\r\n"))
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

func (s *Session) HandleForwardedConnection(conn net.Conn, sshConn *ssh.ServerConn, port uint32) {
	defer conn.Close()
	log.Printf("Handling new forwarded connection from %s", conn.RemoteAddr())
	host, originPort := ParseAddr(conn.RemoteAddr().String())
	payload := createForwardedTCPIPPayload(host, originPort, port)
	channel, reqs, err := sshConn.OpenChannel("forwarded-tcpip", payload)
	if err != nil {
		log.Printf("Failed to open forwarded-tcpip channel: %v", err)
		return
	}
	defer channel.Close()

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	connReader := bufio.NewReader(conn)

	var isHttp bool
	header, err := connReader.Peek(7)

	if err != nil {
		isHttp = false
	} else {
		isHttp = proto.IsHttpRequest(header)
	}

	conn.SetReadDeadline(time.Time{})

	go io.Copy(channel, connReader)

	reader := bufio.NewReader(channel)
	_, err = reader.Peek(1)
	if err == io.EOF {
		if isHttp {
			io.Copy(conn, bytes.NewReader([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 11\r\nContent-Type: text/plain\r\n\r\nBad Gateway")))
		} else {
			conn.Write([]byte("Could not forward request to the tunnel addr\r\n"))
		}
		s.ConnChannels[0].Write([]byte("Could not forward request to the tunnel addr\r\n"))
		return
	} else {
		io.Copy(conn, reader)
	}

	go func() {
		for req := range reqs {
			req.Reply(false, nil)
		}
	}()
}

func (s *Session) GetForwardedConnection(conn net.Conn, host string, sshConn *ssh.ServerConn, payload []byte, originPort, port uint32, path, method, proto string) {
	defer conn.Close()
	channelPayload := createForwardedTCPIPPayload(host, originPort, port)
	channel, reqs, err := sshConn.OpenChannel("forwarded-tcpip", channelPayload)
	if err != nil {
		log.Printf("Failed to open forwarded-tcpip channel: %v", err)
		return
	}
	defer channel.Close()

	connReader := bufio.NewReader(conn)
	initalPayload := bytes.NewReader(payload)
	io.Copy(channel, initalPayload)
	go io.Copy(channel, connReader)

	reader := bufio.NewReader(channel)
	_, err = reader.Peek(1)
	if err == io.EOF {
		io.Copy(conn, bytes.NewReader([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 11\r\nContent-Type: text/plain\r\n\r\nBad Gateway")))
		s.ConnChannels[0].Write([]byte("Could not forward request to the tunnel addr\r\n"))
		return
	} else {
		s.ConnChannels[0].Write([]byte(fmt.Sprintf("\033[32m %s -- [%s] \"%s %s %s\" 	\r\n \033[0m", host, time.Now().Format("02/Jan/2006 15:04:05"), method, path, proto)))
		io.Copy(conn, reader)
	}
	go func() {
		for req := range reqs {
			req.Reply(false, nil)
		}
	}()
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

func createForwardedTCPIPPayload(host string, originPort, port uint32) []byte {
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
