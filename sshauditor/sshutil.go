package sshauditor

import (
	"fmt"
	"net"
	"strings"
	"time"

	log "github.com/inconshreveable/log15"
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

//isPrivateKey returns true if the passed string is a ssh private key instead
//of a password
func isPrivateKey(s string) bool {
	return strings.HasPrefix(s, "-----BEGIN")
}

//DialWithDeadline is identical to ssh.Dial except that it calls SetDeadline on
//the underlying connection
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
		fp := ssh.FingerprintSHA256(key)
		keyFingerprint = fp
		return nil
	}

	user := "security"
	host, _, err := net.SplitHostPort(hostport)
	if err == nil {
		user = fmt.Sprintf("logcheck-%s", host)
	}

	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password("security"),
		},
		HostKeyCallback: DumpHostkey,
		Timeout:         4 * time.Second,
		ClientVersion:   "SSH-2.0-Go-ssh-auditor",
	}

	client, err := DialWithDeadline("tcp", hostport, config)
	if err == nil {
		//This was supposed to fail
		client.Close()
		log.Error("initial probe worked!?!?", "host", hostport, "user", user, "password", "security")
	}
	return keyFingerprint
}

func SSHExecAttempt(client *ssh.Client, hostport string) bool {
	session, err := client.NewSession()
	if err != nil {
		log.Error("successful login but failed to open session", "host", hostport)
		return false
	}
	defer session.Close()
	out, err := session.CombinedOutput("id")
	if err != nil {
		log.Error("successful login but failed to run id", "host", hostport)
		return false
	}
	if isFalsePositiveBanner(string(out)) {
		log.Error("successful login but unexpected id command output", "host", hostport, "output", string(out))
		return false
	}
	return true
}

func SSHDialAttempt(client *ssh.Client, dest string) bool {
	//If there was no error, the dial worked and this is vulnerable!
	conn, err := client.Dial("tcp", dest)
	if err == nil {
		conn.Close()
		return true
	}
	//It may only allow local forwarding, so try replacing the ip with localhost
	log.Error("tunnel attempt failed", "error", err)
	_, port, err := net.SplitHostPort(dest)
	if err != nil {
		log.Error("Invalid host port in SSHDialAttempt, should not happen", "error", err)
		return false
	}
	newDest := fmt.Sprintf("127.0.0.1:%s", port)
	conn, err = client.Dial("tcp", newDest)
	if err == nil {
		conn.Close()
		return true
	}
	log.Error("tunnel attempt failed", "error", err)
	return false
}

func challengeReponder(password string) ssh.KeyboardInteractiveChallenge {
	return func(user, instruction string, questions []string, echos []bool) ([]string, error) {
		answers := make([]string, len(questions))
		for i := range answers {
			answers[i] = password
		}
		return answers, nil
	}
}

func genAuthMethod(password string) ([]ssh.AuthMethod, error) {
	if isPrivateKey(password) {
		signer, err := ssh.ParsePrivateKey([]byte(password))
		if err != nil {
			return []ssh.AuthMethod{}, err
		}

		return []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		}, nil

	}
	return []ssh.AuthMethod{
		ssh.Password(password),
		ssh.KeyboardInteractive(challengeReponder(password)),
	}, nil
}

func SSHAuthAttempt(hostport, user, password string) (string, error) {
	authMethods, err := genAuthMethod(password)
	if err != nil {
		return "", err
	}
	config := &ssh.ClientConfig{
		User:            user,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         4 * time.Second,
		ClientVersion:   "SSH-2.0-Go-ssh-auditor",
	}
	client, err := DialWithDeadline("tcp", hostport, config)
	if err != nil {
		//FIXME: better way?
		if strings.Contains(err.Error(), "unable to authenticate") {
			return "", nil
		}
		return "", err
	}
	//Found a potential weak password!
	defer client.Close()

	execSuccess := SSHExecAttempt(client, hostport)
	if execSuccess {
		return "exec", nil
	}
	//If I was able to authenticate but was unable to run a command, see if port forwarding works

	tcpSuccess := SSHDialAttempt(client, hostport)
	if tcpSuccess {
		return "tunnel", nil
	}
	return "auth", nil
}
