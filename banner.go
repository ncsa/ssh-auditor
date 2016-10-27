package main

import (
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

type ScanResult struct {
	hostport string
	success  bool
	banner   string
}

func ScanPort(hostport string) ScanResult {
	res := ScanResult{hostport: hostport}
	var banner string
	conn, err := net.DialTimeout("tcp", hostport, 2*time.Second)
	if err != nil {
		return res
	}
	defer conn.Close()
	bannerBuffer := make([]byte, 256)
	n, err := conn.Read(bannerBuffer)
	if err == nil {
		banner = string(bannerBuffer[:n])
		banner = strings.TrimRight(banner, "\r\n")
	}
	res.success = true
	res.banner = banner
	return res
}

func bannerWorker(id int, jobs <-chan string, results chan<- ScanResult) {
	for host := range jobs {
		results <- ScanPort(host)
	}
	log.Printf("Worker is done!")
}

func bannerFetcher(numWorkers int, hostports <-chan string) chan ScanResult {
	var wg sync.WaitGroup

	results := make(chan ScanResult, 100)

	for w := 0; w <= numWorkers; w++ {
		wg.Add(1)
		go func() {
			bannerWorker(w, hostports, results)
			wg.Done()
		}()
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	return results
}
