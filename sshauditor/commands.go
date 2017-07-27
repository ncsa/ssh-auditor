package sshauditor

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	log "github.com/inconshreveable/log15"
	"github.com/pkg/errors"
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
	log.Info("discovering hosts",
		"include", strings.Join(cfg.Include, ","),
		"exclude", strings.Join(cfg.Exclude, ","),
		"total", len(hosts),
		"ports", joinInts(cfg.Ports, ","),
	)
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

func checkStore(store *SQLiteStore, hosts chan SSHHost) error {
	knownHosts, err := store.getKnownHosts()
	if err != nil {
		return err
	}
	log.Info("current known hosts", "count", len(knownHosts))
	var totalCount, updatedCount, newCount int
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
				return errors.Wrap(err, "checkStore")
			}
		}
		l := log.New("host", host.hostport, "version", host.version, "fp", host.keyfp)
		if !existing || needUpdate {
			err = store.addOrUpdateHost(host)
			if err != nil {
				return errors.Wrap(err, "checkStore")
			}
		}
		//If it already existed and we didn't otherwise update it, mark that it was seen
		if existing {
			err = store.setLastSeen(host)
			if err != nil {
				return errors.Wrap(err, "checkStore")
			}
		}
		totalCount++
		if !existing {
			l.Info("discovered new host")
			newCount++
		} else if needUpdate {
			l.Info("discovered changed host")
			updatedCount++
		}
	}
	log.Info("discovery report", "total", totalCount, "new", newCount, "updated", updatedCount)
	return nil
}

func updateQueues(store *SQLiteStore) error {
	queued, err := store.initHostCreds()
	if err != nil {
		return err
	}
	queuesize, err := store.getScanQueueSize()
	if err != nil {
		return err
	}
	log.Info("brute force queue size", "new", queued, "total", queuesize)
	return nil
}

func Discover(store *SQLiteStore, cfg ScanConfiguration) error {
	//Push all candidate hosts into the banner fetcher queue
	hostChan, err := discoverHosts(cfg)
	if err != nil {
		return err
	}

	portResults := bannerFetcher(1024, hostChan)
	keyResults := fingerPrintFetcher(512, portResults)

	err = checkStore(store, keyResults)
	if err != nil {
		return err
	}

	err = updateQueues(store)
	return err
}

func brute(store *SQLiteStore, scantype string) error {
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
		return errors.Wrap(err, "Error getting scan queue")
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
		l := log.New(
			"host", br.host.Hostport,
			"user", br.cred.User,
			"password", br.cred.Password,
			"result", br.result,
		)
		if br.err != nil {
			l.Error("brute force error", "err", br.err.Error())
		} else if br.result == "" {
			l.Debug("negative brute force result")
		} else {
			l.Info("positive brute force result")
		}
		err = store.updateBruteResult(br)
		if err != nil {
			return err
		}
	}
	return nil
}

func Scan(store *SQLiteStore) error {
	return brute(store, "scan")
}
func Rescan(store *SQLiteStore) error {
	return brute(store, "rescan")
}

func Dupes(store *SQLiteStore) error {
	//FIXME: return DATA here
	return store.duplicateKeyReport()
}

func Logcheck(store *SQLiteStore) error {
	sc, err := store.getLogCheckQueue()
	if err != nil {
		return err
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
		l := log.New("host", br.host.Hostport, "user", br.cred.User)
		if br.err != nil {
			l.Error("Failed to send logcheck auth request", "error", br.err)
			continue
		}
		l.Info("Sent logcheck auth request")
		//TODO Collect hostports and return them for syslog cross referencing
	}
	return nil
}
func LogcheckReport(store *SQLiteStore, ls LogSearcher) error {
	activeHosts, err := store.GetActiveHosts()
	if err != nil {
		return errors.Wrap(err, "LogcheckReport GetActiveHosts failed")
	}

	foundIPs, err := ls.GetIPs()
	if err != nil {
		return errors.Wrap(err, "LogcheckReport GetIPs failed")
	}

	logPresent := make(map[string]bool)
	for _, host := range foundIPs {
		logPresent[host] = true
	}

	log.Info("found active hosts in store", "count", len(activeHosts))
	log.Info("found related hosts in logs", "count", len(foundIPs))

	for _, host := range activeHosts {
		ip, _, err := net.SplitHostPort(host.Hostport)
		if err != nil {
			log.Error("invalid hostport", "host", host.Hostport)
			continue
		}
		fmt.Printf("%s %v\n", host.Hostport, logPresent[ip])
	}
	return nil
}

func Vulnerabilities(store *SQLiteStore) error {
	vulns, err := store.GetVulnerabilities()
	if err != nil {
		return errors.Wrap(err, "Vulnerabilities GetVulnerabilities failed")
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
	return nil
}
