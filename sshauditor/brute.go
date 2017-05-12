package sshauditor

import "sync"

type ScanRequest struct {
	host        Host
	credentials []Credential
}

type BruteForceResult struct {
	host   Host
	cred   Credential
	result string
}

func bruteworker(id int, jobs <-chan ScanRequest, results chan<- BruteForceResult) {
	for sr := range jobs {
		for _, cred := range sr.credentials {
			res := BruteForceResult{
				host:   sr.host,
				cred:   cred,
				result: SSHAuthAttempt(sr.host.Hostport, cred.User, cred.Password),
			}
			results <- res
		}
	}
}

func bruteForcer(numWorkers int, hosts <-chan ScanRequest) chan BruteForceResult {
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
