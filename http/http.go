package httpServer

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"strings"
	"tunnel_pls/session"
)

//func ExtractDomain(conn net.Conn) (string, error) {
//	defer conn.SetReadDeadline(time.Time{})               // Reset timeout after reading
//	conn.SetReadDeadline(time.Now().Add(2 * time.Second)) // Prevent hanging
//
//	reader := bufio.NewReader(conn)
//	for {
//		line, err := reader.ReadString('\n')
//		if err != nil {
//			return "", err
//		}
//
//		line = strings.TrimSpace(line)
//		if strings.HasPrefix(strings.ToLower(line), "host:") {
//			return strings.TrimSpace(strings.SplitN(line, ":", 2)[1]), nil
//		}
//
//		if line == "" {
//			break
//		}
//	}
//
//	return "", fmt.Errorf("host header not found")
//}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	sshSession := session.Clients["test"]
	sshSession.HandleForwardedConnection(conn, sshSession.Connection, 80)
}

func getHost(data []byte) string {
	lines := bytes.Split(data, []byte("\n"))
	for _, line := range lines {
		fmt.Println("here")
		if bytes.HasPrefix(line, []byte("Host: ")) {
			return strings.TrimSpace(string(line[6:]))
		}
	}
	return ""
}

func Listen() {
	listen, err := net.Listen("tcp", ":80")
	if err != nil {
		log.Fatal("Error starting server:", err)
	}
	defer listen.Close()

	fmt.Println("Server listening on port 80")

	for {
		conn, err := listen.Accept()
		if err != nil {
			log.Println("Error accepting connection:", err)
			continue
		}

		go handleConnection(conn)
	}
}
