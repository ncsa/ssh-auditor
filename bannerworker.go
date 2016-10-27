package main

import "sync"

func bannerWorker(id int, jobs <-chan string, results chan<- ScanResult) {
	for host := range jobs {
		results <- ScanPort(host)
	}
}

func bannerFetcher(numWorkers int, hostports <-chan string) chan ScanResult {
	var wg sync.WaitGroup

	results := make(chan ScanResult, 1000)

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
