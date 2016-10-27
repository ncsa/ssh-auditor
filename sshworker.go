package main

import "sync"

type SSHHost struct {
	hostport string
	version  string
	keyfp    string
}

func keyworker(id int, jobs <-chan ScanResult, results chan<- SSHHost) {
	for host := range jobs {
		if !host.success {
			continue
		}
		res := SSHHost{
			hostport: host.hostport,
			version:  host.banner,
			keyfp:    FetchSSHKeyFingerprint(host.hostport),
		}
		results <- res
	}
}

func fingerPrintFetcher(numWorkers int, scanResults <-chan ScanResult) chan SSHHost {
	var wg sync.WaitGroup

	results := make(chan SSHHost, 1000)

	for w := 0; w <= numWorkers; w++ {
		wg.Add(1)
		go func() {
			keyworker(w, scanResults, results)
			wg.Done()
		}()
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	return results
}
