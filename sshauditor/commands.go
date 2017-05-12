package sshauditor

import (
	"fmt"
	"log"
	"strconv"
	"strings"
)

type ScanConfiguration struct {
	Include []string
	Exclude []string
	Ports   []int
}

func joinInts(ints []int, sep string) string {
	var foo []string
	for _, i := range ints {
		foo = append(foo, strconv.Itoa(i))
	}
	return strings.Join(foo, sep)
}

func discoverHosts(cfg ScanConfiguration) (chan string, error) {
	hostChan := make(chan string, 1024)
	hosts, err := EnumerateHosts(cfg.Include, cfg.Exclude)
	if err != nil {
		return hostChan, err
	}
	log.Printf("Discovering %d potential hosts on ports %s", len(hosts), joinInts(cfg.Ports, ","))
	go func() {
		// Iterate over ports first, so for a large scan there's a
		// delay between attempts per host
		for _, port := range cfg.Ports {
			for _, h := range hosts {
				hostChan <- fmt.Sprintf("%s:%d", h, port)
			}
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
			var needUpdate bool
			rec, existing := knownHosts[host.hostport]
			if existing {
				if host.keyfp == "" {
					host.keyfp = rec.Fingerprint
				}
				if host.version == "" {
					host.version = rec.Version
				}
				needUpdate = (host.keyfp != rec.Fingerprint || host.version != rec.Version)
				err := store.addHostChanges(host, rec)
				if err != nil {
					log.Fatal(err)
				}
			}
			if !existing || needUpdate {
				err = store.addOrUpdateHost(host)
				if err != nil {
					log.Fatal(err)
				}
				newHosts <- host
			}
			//If it already existed and we didn't otherwise update it, mark that it was seen
			if existing {
				err = store.setLastSeen(host)
				if err != nil {
					log.Fatal(err)
				}
			}
		}
		close(newHosts)
	}()
	return newHosts
}

func Discover(store *SQLiteStore, cfg ScanConfiguration) {
	//Push all candidate hosts into the banner fetcher queue
	hostChan, err := discoverHosts(cfg)
	if err != nil {
		log.Fatal(err)
	}

	portResults := bannerFetcher(1024, hostChan)
	keyResults := fingerPrintFetcher(512, portResults)

	newHosts := checkStore(store, keyResults)

	for host := range newHosts {
		log.Print("New or Changed Host", host)
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
		if br.result != "" {
			log.Printf("Result %s %s %s", br.host.Hostport, br.cred, br.result)
		}
		if br.err != nil {
			log.Printf("Result %s %s", br.host.Hostport, br.err)
		}
		err = store.updateBruteResult(br)
		if err != nil {
			log.Fatal(err)
		}
	}
}

func Scan(store *SQLiteStore) {
	brute(store, "scan")
}
func Rescan(store *SQLiteStore) {
	brute(store, "rescan")
}

func Dupes(store *SQLiteStore) {
	store.duplicateKeyReport()
}

func Logcheck(store *SQLiteStore) {
	sc, err := store.getLogCheckQueue()
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
		log.Printf("Sent logcheck auth request for %s %s", br.host.Hostport, br.cred.User)
	}
}
