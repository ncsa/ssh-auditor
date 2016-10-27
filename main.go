package main

import "log"

func discoverHosts(store *SQLiteStore, hosts []string) error {
	knownHosts, err := store.getKnownHosts()
	if err != nil {
		return err
	}
	log.Printf("Known hosts=%d", len(knownHosts))
	return nil
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

	netblocks := []string{"192.168.2.0/24"}
	exclude := []string{"192.168.2.0/30"}

	hosts, err := EnumerateHosts(netblocks, exclude)
	if err != nil {
		log.Fatal(err)
	}

	err = discoverHosts(store, hosts)
	if err != nil {
		log.Fatal(err)
	}
	return

	hostChan := make(chan string, 100)
	portResults := bannerFetcher(128, hostChan)

	return
	keyResults := fingerPrintFetcher(128, portResults)
	bruteResults := bruteForcer(128, keyResults)

	log.Printf("Testing %d hosts", len(hosts))

	//Push all candidate hosts into the banner fetcher queue
	go func() {
		for _, h := range hosts {
			hostChan <- h + ":22"
		}
		close(hostChan)
	}()

	for br := range bruteResults {
		if br.success {
			log.Printf("%v", br)
		}
	}

}
