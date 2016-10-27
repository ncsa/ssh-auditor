package main

import (
	"log"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

type SSHHost struct {
	hostport string
	version  string
	keyfp    string
}

func keyworker(id int, jobs <-chan ScanResult, results chan<- SSHHost) {
	for host := range jobs {
		res := SSHHost{
			hostport: host.hostport,
			version:  host.banner,
			keyfp:    FetchSSHKeyFingerprint(host.hostport),
		}
		results <- res
	}
}

func FetchSSHKeyFingerprints(hosts []ScanResult) []SSHHost {
	var sshHosts []SSHHost
	jobs := make(chan ScanResult, 100)
	results := make(chan SSHHost, 100)

	for w := 1; w <= 128; w++ {
		go keyworker(w, jobs, results)
	}
	go func() {
		for _, hostport := range hosts {
			jobs <- hostport
		}
		close(jobs)
	}()
	for i := 0; i < len(hosts); i++ {
		res := <-results
		sshHosts = append(sshHosts, res)
	}
	return sshHosts
}

func SSHAuthAttempt(host, user, password string) bool {
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		Timeout: 2 * time.Second,
	}

	conn, err := net.DialTimeout("tcp", host, config.Timeout)
	if err != nil {
		//log.Print("Failed to dial: ", err)
		return false
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, host, config)
	if err != nil {
		//log.Print("Failed to dial: ", err)
		return false
	}
	client := ssh.NewClient(c, chans, reqs)
	session, err := client.NewSession()
	if err != nil {
		//log.Print("Failed to create session: ", err)
		return false
	}
	defer session.Close()
	return true
}

func main() {
	netblocks := []string{"192.168.2.0/24"}
	exclude := []string{"192.168.2.0/30"}

	hosts, err := EnumerateHosts(netblocks, exclude)
	if err != nil {
		log.Fatal(err)
	}

	hostChan := make(chan string, 100)

	portResults := bannerFetcher(128, hostChan)
	log.Printf("Testing %d hosts", len(hosts))

	go func() {
		for _, h := range hosts {
			hostChan <- h + ":22"
		}
		close(hostChan)
	}()

	for res := range portResults {
		if res.success {
			log.Printf("%+v", res)
		}
	}

	/*
		listening := FindSSH(hosts)
		log.Printf("SSH ON %d hosts", len(listening))

		fingerprints := FetchSSHKeyFingerprints(listening)
		for _, h := range fingerprints {
			log.Printf("SSH %+v", h)
			continue
		}
	*/

}
