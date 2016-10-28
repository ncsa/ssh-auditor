package main

import (
	"log"
	"os"
)

type ScanConfiguration struct {
	include []string
	exclude []string
}

func discoverHosts(cfg ScanConfiguration) (chan string, error) {
	hostChan := make(chan string, 1024)
	hosts, err := EnumerateHosts(cfg.include, cfg.exclude)
	if err != nil {
		return hostChan, err
	}
	log.Printf("Discovering %d potential hosts", len(hosts))
	go func() {
		for _, h := range hosts {
			hostChan <- h + ":22"
		}
		close(hostChan)
	}()
	return hostChan, err
}

func checkStore(store *SQLiteStore, hosts chan SSHHost) chan SSHHost {
	knownHosts, err := store.getKnownHosts()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Known host count=%d", len(knownHosts))
	newHosts := make(chan SSHHost, 1000)
	go func() {
		for host := range hosts {
			rec, existing := knownHosts[host.hostport]
			if !existing || rec.Fingerprint != host.keyfp || rec.Version != host.version {
				err = store.addOrUpdateHost(host)
				if err != nil {
					log.Fatal(err)
				}
				newHosts <- host
			}
		}
		close(newHosts)
	}()
	return newHosts
}

func discover(store *SQLiteStore, cfg ScanConfiguration) {
	//Push all candidate hosts into the banner fetcher queue
	hostChan, err := discoverHosts(cfg)
	if err != nil {
		log.Fatal(err)
	}

	portResults := bannerFetcher(1024, hostChan)
	keyResults := fingerPrintFetcher(512, portResults)

	newHosts := checkStore(store, keyResults)

	for host := range newHosts {
		log.Print("New host", host)
	}
	queued, err := store.initHostCreds()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("queued %d credential checks", queued)
}

func brute(store *SQLiteStore, scantype string) {
	var err error
	queued, err := store.initHostCreds()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("queued %d credential checks", queued)

	var sc []ScanRequest
	switch scantype {
	case "scan":
		sc, err = store.getScanQueue()
	case "rescan":
		sc, err = store.getRescanQueue()
	}
	if err != nil {
		log.Fatal(err)
	}

	bruteChan := make(chan ScanRequest, 1024)
	go func() {
		for _, sr := range sc {
			bruteChan <- sr
		}
		close(bruteChan)
	}()

	bruteResults := bruteForcer(256, bruteChan)

	for br := range bruteResults {
		store.updateBruteResult(br)
	}
}

func main() {

	store, err := NewSQLiteStore("ssh_db.sqlite")
	if err != nil {
		log.Fatal(err)
	}
	err = store.Init()
	if err != nil {
		log.Fatal(err)
	}

	switch os.Args[1] {
	case "discover":
		scanConfig := ScanConfiguration{
			include: os.Args[2:],
			exclude: []string{},
		}
		log.Print(scanConfig)

		discover(store, scanConfig)
	case "scan":
		brute(store, "scan")
	case "rescan":
		brute(store, "rescan")
	}
}
