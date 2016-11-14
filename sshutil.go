package main

import (
	"crypto/sha256"
	"encoding/base64"
	"log"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

var falsePositiveBanners = [...]string{
	"Auth User/Pass with PS...fail...Please reconnect",
}

//isFalsePositiveBanner returns true if the ssh login banner
//appears to be a false positive.  This could probably just check
//for the presense of 'uid=' but for now, check for known banners
func isFalsePositiveBanner(output string) bool {
	for _, b := range falsePositiveBanners {
		if strings.Contains(output, b) {
			return true
		}
	}
	return false
}

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
		log.Printf("BADPW %s: user=security password=security", hostport)
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
	if err != nil {
		return false
	}
	//Found a potential weak password!
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		log.Printf("Successful login to %s but failed to open session", hostport)
		return false
	}
	defer session.Close()

	out, err := session.CombinedOutput("id")
	if err != nil {
		log.Printf("Successful login to %s but failed to run id", hostport)
		return false
	}
	if isFalsePositiveBanner(string(out)) {
		log.Printf("Successful login to %s but id command output %s", hostport, out)
		return false
	}
	return true
}
