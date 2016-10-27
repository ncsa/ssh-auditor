package main

import (
	"log"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

func worker(id int, jobs <-chan string, results chan<- ScanResult) {
	for host := range jobs {
		results <- ScanPort(host)
	}
}

func FindSSH(hosts []string) []ScanResult {
	var listeningHosts []ScanResult
	jobs := make(chan string, 100)
	results := make(chan ScanResult, 100)

	for w := 1; w <= 128; w++ {
		go worker(w, jobs, results)
	}
	go func() {
		for _, host := range hosts {
			hostport := host + ":2221"
			jobs <- hostport
		}
		close(jobs)
	}()
	for i := 0; i < len(hosts); i++ {
		res := <-results
		if res.success {
			listeningHosts = append(listeningHosts, res)
		}
	}
	return listeningHosts
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

	log.Printf("Testing %d hosts", len(hosts))
	listening := FindSSH(hosts)
	log.Printf("SSH ON %d hosts", len(listening))
	for _, h := range listening {
		fp := FetchSSHKeyFingerPrint(h.hostport)
		log.Printf("SSH %s %s %s", h.hostport, h.banner, fp)
		continue
		res := SSHAuthAttempt(h.hostport, "root", "root")
		if res {
			log.Printf("BADPW %s (%s): auth result: %v", h.hostport, h.banner, res)
		}
	}

}
