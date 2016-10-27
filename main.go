package main

import "log"

func main() {
	netblocks := []string{"192.168.2.0/24"}
	exclude := []string{"192.168.2.0/30"}

	hosts, err := EnumerateHosts(netblocks, exclude)
	if err != nil {
		log.Fatal(err)
	}

	hostChan := make(chan string, 100)
	sshHostChan := make(chan ScanResult, 100)

	portResults := bannerFetcher(128, hostChan)
	keyResults := fingerPrintFetcher(128, sshHostChan)

	log.Printf("Testing %d hosts", len(hosts))

	//Push all candidate hosts into the banner fetcher queue
	go func() {
		for _, h := range hosts {
			hostChan <- h + ":22"
		}
		close(hostChan)
	}()

	//Consume from open port results and push into fingerprint queue
	go func() {
		for res := range portResults {
			if res.success {
				sshHostChan <- res
			}
		}
		close(sshHostChan)
	}()

	for kr := range keyResults {
		log.Printf("%v", kr)
	}

}
