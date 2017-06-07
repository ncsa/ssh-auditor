package sshauditor

import (
	"fmt"
	"log"
	"net"
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

func updateQueues(store *SQLiteStore) {
	queued, err := store.initHostCreds()
	if err != nil {
		log.Fatal(err)
	}
	if queued > 0 {
		log.Printf("queued %d new credential checks", queued)
	}
	queuesize, err := store.getScanQueueSize()
	if err != nil {
		log.Fatal(err)
	}
	if queuesize > 0 {
		log.Printf("%d total credential checks queued", queuesize)
	}
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
	updateQueues(store)
}

func brute(store *SQLiteStore, scantype string) {
	updateQueues(store)
	var err error

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
		log.Printf("Result %s %s %s", br.host.Hostport, br.cred, br.result)
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
		if br.err != nil {
			log.Printf("Failed to send logcheck auth request for %s %s %s", br.host.Hostport, br.cred.User, br.err)
			continue
		}
		log.Printf("Sent logcheck auth request for %s %s", br.host.Hostport, br.cred.User)
		//TODO Collect hostports and return them for syslog cross referencing
	}
}
func LogcheckReport(store *SQLiteStore, ls LogSearcher) {
	activeHosts, err := store.GetActiveHosts()
	if err != nil {
		log.Fatal(err)
	}

	foundIPs, err := ls.GetIPs()
	if err != nil {
		log.Fatal(err)
	}

	logPresent := make(map[string]bool)
	for _, host := range foundIPs {
		logPresent[host] = true
	}

	//log.Printf("%d active hosts", len(activeHosts))
	//log.Printf("Found %d IPs in logs", len(foundIPs))

	for _, host := range activeHosts {
		ip, _, err := net.SplitHostPort(host.Hostport)
		if err != nil {
			log.Printf("invalid hostport for: %v", host)
			continue
		}
		fmt.Printf("%s %v", host.Hostport, logPresent[ip])
	}
}

func Vulnerabilities(store *SQLiteStore) {
	vulns, err := store.GetVulnerabilities()
	if err != nil {
		log.Fatal(err)
	}
	for _, v := range vulns {
		fmt.Printf("%s\t%s\t%s\t%s\t%s\t%s\n",
			v.Host.Hostport,
			v.HostCredential.User,
			v.HostCredential.Password,
			v.HostCredential.Result,
			v.HostCredential.LastTested,
			v.Host.Version,
		)
	}
}
