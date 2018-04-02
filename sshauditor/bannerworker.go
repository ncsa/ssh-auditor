package sshauditor

import "sync"

func bannerWorker(jobs <-chan string, results chan<- ScanResult) {
	for host := range jobs {
		results <- ScanPort(host)
	}
}

func bannerFetcher(numWorkers int, hostports <-chan string) chan ScanResult {
	var wg sync.WaitGroup

	results := make(chan ScanResult, 1024)

	for w := 0; w <= numWorkers; w++ {
		wg.Add(1)
		go func() {
			bannerWorker(hostports, results)
			wg.Done()
		}()
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	return results
}
