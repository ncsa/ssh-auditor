package main

import "log"

type ScanConfiguration struct {
	include []string
	exclude []string
}

func discoverHosts(cfg ScanConfiguration) (chan string, error) {
	hostChan := make(chan string, 100)
	hosts, err := EnumerateHosts(cfg.include, cfg.exclude)
	if err != nil {
		return hostChan, err
	}
	log.Printf("Disocovering %d potential hosts", len(hosts))
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
				log.Print("New host", host)
				newHosts <- host
			}
		}
		close(newHosts)
	}()
	return newHosts
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

	scanConfig := ScanConfiguration{
		include: []string{"192.168.2.0/24"},
		exclude: []string{"192.168.2.0/30"},
	}

	//Push all candidate hosts into the banner fetcher queue
	hostChan, err := discoverHosts(scanConfig)
	if err != nil {
		log.Fatal(err)
	}

	portResults := bannerFetcher(128, hostChan)
	keyResults := fingerPrintFetcher(128, portResults)

	newHosts := checkStore(store, keyResults)

	bruteResults := bruteForcer(128, newHosts)

	for br := range bruteResults {
		if br.success {
			log.Printf("%v", br)
		}
	}

}
