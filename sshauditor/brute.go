package sshauditor

import "sync"

type ScanRequest struct {
	hostport    string
	credentials []Credential
}

type BruteForceResult struct {
	hostport string
	cred     Credential
	err      error
	result   string
}

func bruteworker(jobs <-chan ScanRequest, results chan<- BruteForceResult) {
	for sr := range jobs {
		failures := 0
		for _, cred := range sr.credentials {
			//TODO: make this configurable
			//After 5 connection errors, stop trying this host for this run
			if failures > 5 {
				continue
			}
			result, err := SSHAuthAttempt(sr.hostport, cred.User, cred.Password)
			res := BruteForceResult{
				hostport: sr.hostport,
				cred:     cred,
				result:   result,
				err:      err,
			}
			results <- res
			if err != nil {
				failures++
			}
		}
	}
}

func bruteForcer(numWorkers int, requests []ScanRequest) chan BruteForceResult {
	var wg sync.WaitGroup

	requestChan := make(chan ScanRequest, numWorkers)
	go func() {
		for _, sr := range requests {
			requestChan <- sr
		}
		close(requestChan)
	}()
	results := make(chan BruteForceResult, 1000)

	for w := 0; w <= numWorkers; w++ {
		wg.Add(1)
		go func() {
			bruteworker(requestChan, results)
			wg.Done()
		}()
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	return results
}
