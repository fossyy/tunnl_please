package main

import (
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"tunnel_pls/server"
	"tunnel_pls/utils"

	"golang.org/x/crypto/ssh"
)

func main() {
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()
	sshConfig := &ssh.ServerConfig{
		NoClientAuth:  true,
		ServerVersion: "SSH-2.0-TunnlPls-1.0",
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			return nil, nil
		},
	}

	log.SetOutput(os.Stdout)
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	privateBytes, err := os.ReadFile(utils.Getenv("ssh_private_key"))
	if err != nil {
		log.Fatalf("Failed to load private key : %s", err.Error())
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		log.Fatal("Failed to parse private key")
	}

	sshConfig.AddHostKey(private)
	app := server.NewServer(*sshConfig)
	app.Start()
}
