package main

import (
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func EnumerateHosts(netblocks []string, exclude []string) ([]string, error) {
	var hosts []string
	excludeHosts := make(map[string]bool)
	for _, netblock := range exclude {
		ip, ipnet, err := net.ParseCIDR(netblock)
		if err != nil {
			return hosts, err
		}

		for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
			excludeHosts[ip.String()] = true
		}
	}

	for _, netblock := range netblocks {
		ip, ipnet, err := net.ParseCIDR(netblock)
		if err != nil {
			return hosts, err
		}
		for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
			if _, excluded := excludeHosts[ip.String()]; !excluded {
				hosts = append(hosts, ip.String())
			}
		}
	}
	return hosts, nil
}

type ScanResult struct {
	host    string
	success bool
	version string
}

func CheckSSH(host string) ScanResult {
	var version string
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, 22), 2*time.Second)
	if err == nil {
		defer conn.Close()
		versionBuffer := make([]byte, 256)
		n, err := conn.Read(versionBuffer)
		if err == nil {
			version = string(versionBuffer[:n])
			version = strings.TrimRight(version, "\r\n")
		}
		return ScanResult{
			host:    host,
			success: true,
			version: version,
		}
	}
	return ScanResult{host: host, success: false, version: ""}
}

func worker(id int, jobs <-chan string, results chan<- ScanResult) {
	for host := range jobs {
		results <- CheckSSH(host)
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
			jobs <- host
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

func DumpHostkey(hostname string, remote net.Addr, key ssh.PublicKey) error {
	log.Println(hostname, remote, key.Marshal())
	return nil
}

func DumpSSH(host string) {
	config := &ssh.ClientConfig{
		User: "security",
		Auth: []ssh.AuthMethod{
			ssh.Password("security"),
		},
		HostKeyCallback: DumpHostkey,
		Timeout:         2 * time.Second,
	}

	conn, err := net.DialTimeout("tcp", host, config.Timeout)
	if err != nil {
		log.Print("Failed to dial: ", err)
		return
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, host, config)
	if err != nil {
		log.Print("Failed to dial: ", err)
		return
	}
	client := ssh.NewClient(c, chans, reqs)
	session, err := client.NewSession()
	if err != nil {
		log.Print("Failed to create session: ", err)
		return
	}
	defer session.Close()

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
		//log.Printf("SSH ON %v", h)
		//DumpSSH(h.host + ":22")
		res := SSHAuthAttempt(h.host+":22", "root", "root")
		if res {
			log.Printf("XXXXXXXXXXXXX %v: auth result: %v", h, res)
		}
	}

}
