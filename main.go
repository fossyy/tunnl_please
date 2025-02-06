package main

import (
	"golang.org/x/crypto/ssh"
	"log"
	"os"
	"tunnel_pls/server"
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
	app := server.NewServer(*sshConfig)
	app.Start()
}
