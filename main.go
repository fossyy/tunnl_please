package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"
	"log"
	"net"
	"os"
	"strconv"
)

func main() {
	sshConfig := &ssh.ServerConfig{
		NoClientAuth: true,
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			return nil, nil
		},
	}

	privateBytes, err := os.ReadFile("id_rsa")
	if err != nil {
		log.Fatal("Failed to load private key (./id_rsa)")
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		log.Fatal("Failed to parse private key")
	}

	sshConfig.AddHostKey(private)
	listen, err := net.Listen("tcp", ":2200")
	if err != nil {
		log.Fatal(err)
		return
	}
	log.Println("Listening on port 2200")

	for {
		tcpConn, err := listen.Accept()
		if err != nil {
			log.Fatal(err)
			return
		}
		sshConn, connChan, globalConnChan, err := ssh.NewServerConn(tcpConn, sshConfig)
		if err != nil {
			log.Printf("Failed to handshake (%s)", err)
			continue
		}
		log.Printf("New SSH connection from %s (%s) with User (%s)", sshConn.RemoteAddr(), sshConn.ClientVersion(), sshConn.User())

		go handleRequests(globalConnChan, sshConn)
		go handleChannels(connChan, sshConn)
	}
}

func handleChannels(chans <-chan ssh.NewChannel, sshConn *ssh.ServerConn) {
	for newChannel := range chans {
		go handleChannel(newChannel, sshConn)
	}
}

func handleRequests(reqs <-chan *ssh.Request, sshConn *ssh.ServerConn) {
	for req := range reqs {
		log.Printf("Received global request: %s", req.Type)

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

			log.Printf("Requested forwarding on %s:%d", addr, portToBind)

			listener, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", portToBind))
			if err != nil {
				log.Printf("Failed to bind to port %d: %v", portToBind, err)
				req.Reply(false, nil)
				continue
			}

			go func() {
				for {
					conn, err := listener.Accept()
					if err != nil {
						log.Printf("Error accepting connection: %v", err)
						continue
					}
					go handleForwardedConnection(conn, sshConn, portToBind)
				}
			}()

			buf := new(bytes.Buffer)
			binary.Write(buf, binary.BigEndian, uint32(portToBind))

			log.Printf("Forwarding approved on port: %d", portToBind)
			req.Reply(true, buf.Bytes())
		} else {
			req.Reply(false, nil)
		}
	}
}

func handleForwardedConnection(conn net.Conn, sshConn *ssh.ServerConn, port uint32) {
	defer conn.Close()
	log.Printf("Handling new forwarded connection from %s", conn.RemoteAddr())

	payload := createForwardedTCPIPPayload(conn, port)
	channel, reqs, err := sshConn.OpenChannel("forwarded-tcpip", payload)
	if err != nil {
		log.Printf("Failed to open forwarded-tcpip channel: %v", err)
		return
	}
	defer channel.Close()

	go io.Copy(channel, conn)
	io.Copy(conn, channel)

	go func() {
		for req := range reqs {
			req.Reply(false, nil)
		}
	}()
}

func handleChannel(newChannel ssh.NewChannel, sshConn *ssh.ServerConn) {
	switch newChannel.ChannelType() {
	case "session":
		handleSessionChannel(newChannel)

	case "forwarded-tcpip":
		//handleForwardedTCPIP(newChannel)
	default:
		newChannel.Reject(ssh.UnknownChannelType, "unsupported channel type")
	}
}

func handleSessionChannel(newChannel ssh.NewChannel) {
	connection, requests, err := newChannel.Accept()
	if err != nil {
		log.Printf("Could not accept channel: %s", err)
		return
	}
	var bandwidth uint32
	go func() {
		var commandBuffer bytes.Buffer
		buf := make([]byte, 1)
		for {
			n, err := connection.Read(buf)
			bandwidth += uint32(n)
			fmt.Println("using ", bandwidth)
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
						fmt.Println("User entered command:", command)

						if command == "/bye" {
							fmt.Println("Closing connection...")
							connection.Close()
							return
						} else if command == "/help" {
							connection.Write([]byte("Available commands: /bye, /help"))
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
		connection.Write([]byte("hello world"))
		for req := range requests {
			switch req.Type {
			case "shell", "pty-req":
				req.Reply(true, nil)
			default:
				fmt.Println("Unknown request type")
				req.Reply(false, nil)
			}
		}
	}()
}

//func handleForwardedTCPIP(newChannel ssh.NewChannel) {
//	reader := bytes.NewReader(newChannel.ExtraData())
//
//	destAddr, err := readSSHString(reader)
//	if err != nil {
//		log.Println("Failed to read destination address:", err)
//		newChannel.Reject(ssh.ConnectionFailed, "invalid destination")
//		return
//	}
//
//	var destPort uint32
//	if err := binary.Read(reader, binary.BigEndian, &destPort); err != nil {
//		log.Println("Failed to read destination port:", err)
//		newChannel.Reject(ssh.ConnectionFailed, "invalid port")
//		return
//	}
//
//	log.Printf("Forwarding connection to %s:%d", destAddr, destPort)
//
//	targetConn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", destAddr, destPort))
//	fmt.Println("connected to", destAddr)
//	if err != nil {
//		log.Printf("Failed to connect to %s:%d: %v", destAddr, destPort, err)
//		newChannel.Reject(ssh.ConnectionFailed, "could not connect to target")
//		return
//	}
//
//	channel, _, err := newChannel.Accept()
//	if err != nil {
//		log.Printf("Could not accept forwarded channel: %v", err)
//		targetConn.Close()
//		return
//	}
//
//	go io.Copy(channel, targetConn)
//	go io.Copy(targetConn, channel)
//}

func writeSSHString(buffer *bytes.Buffer, str string) {
	binary.Write(buffer, binary.BigEndian, uint32(len(str)))
	buffer.WriteString(str)
}

func parseAddr(addr string) (string, int) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		log.Println("Failed to parse origin address:", err)
		return "0.0.0.0", 0
	}
	port, _ := strconv.Atoi(portStr)
	return host, port
}

func createForwardedTCPIPPayload(conn net.Conn, port uint32) []byte {
	var buf bytes.Buffer
	host, originPort := parseAddr(conn.RemoteAddr().String())

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
