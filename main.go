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

	go func() {
		for _, h := range hosts {
			hostChan <- h + ":22"
		}
		close(hostChan)
	}()

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

	/*
		listening := FindSSH(hosts)
		log.Printf("SSH ON %d hosts", len(listening))

		fingerprints := FetchSSHKeyFingerprints(listening)
		for _, h := range fingerprints {
			log.Printf("SSH %+v", h)
			continue
		}
	*/

}
