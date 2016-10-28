package main

import (
	"crypto/sha256"
	"encoding/base64"
	"log"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

func hashKey(key ssh.PublicKey) string {
	hash := sha256.Sum256(key.Marshal())
	fp := base64.RawStdEncoding.EncodeToString(hash[:])
	return fp
}

func DialWithDeadline(network, addr string, config *ssh.ClientConfig) (*ssh.Client, error) {
	conn, err := net.DialTimeout(network, addr, config.Timeout)
	if err != nil {
		return nil, err
	}

	//This call to SetDeadline is the only difference from ssh.Dial
	conn.SetDeadline(time.Now().Add(2 * config.Timeout))
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		return nil, err
	}
	return ssh.NewClient(c, chans, reqs), nil
}

func FetchSSHKeyFingerprint(hostport string) string {

	var keyFingerprint string

	DumpHostkey := func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		fp := hashKey(key)
		keyFingerprint = fp
		return nil
	}

	config := &ssh.ClientConfig{
		User: "security",
		Auth: []ssh.AuthMethod{
			ssh.Password("security"),
		},
		HostKeyCallback: DumpHostkey,
		Timeout:         4 * time.Second,
	}

	client, err := DialWithDeadline("tcp", hostport, config)
	if err == nil {
		//This was supposed to fail
		client.Close()
		log.Printf("BADPW %s (%s): user=security password=security", hostport)
	}
	return keyFingerprint
}

func SSHAuthAttempt(hostport, user, password string) bool {
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		Timeout: 4 * time.Second,
	}
	client, err := DialWithDeadline("tcp", hostport, config)
	if err == nil {
		//Found a weak password!
		client.Close()
		return true
	}
	return false

}
