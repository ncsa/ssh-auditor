package sshauditor

import "sync"

type ScanRequest struct {
	host        Host
	credentials []Credential
}

type BruteForceResult struct {
	host   Host
	cred   Credential
	err    error
	result string
}

func bruteworker(id int, jobs <-chan ScanRequest, results chan<- BruteForceResult) {
	for sr := range jobs {
		failures := 0
		for _, cred := range sr.credentials {
			//TODO: make this configurable
			//After 5 connection errors, stop trying this host for this run
			if failures > 5 {
				continue
			}
			result, err := SSHAuthAttempt(sr.host.Hostport, cred.User, cred.Password)
			res := BruteForceResult{
				host:   sr.host,
				cred:   cred,
				result: result,
				err:    err,
			}
			results <- res
			if err != nil {
				failures++
			}
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
