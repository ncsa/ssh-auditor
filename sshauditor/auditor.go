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
	Include     []string
	Exclude     []string
	Ports       []int
	Concurrency int
}
type AuditResult struct {
	totalCount int
	negCount   int
	posCount   int
	errCount   int
}

func joinInts(ints []int, sep string) string {
	var foo []string
	for _, i := range ints {
		foo = append(foo, strconv.Itoa(i))
	}
	return strings.Join(foo, sep)
}

//expandScanConfiguration takes a ScanConfiguration and returns a channel
//of all hostports that match the scan configuration.
func expandScanConfiguration(cfg ScanConfiguration) (chan string, error) {
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

type SSHAuditor struct {
	//TODO: should be interface
	store *SQLiteStore
}

func New(store *SQLiteStore) *SSHAuditor {
	return &SSHAuditor{
		store: store,
	}
}

func (a *SSHAuditor) updateStoreFromDiscovery(hosts chan SSHHost) error {
	_, err := a.store.Begin()
	defer a.store.Commit()
	if err != nil {
		return errors.Wrap(err, "updateStoreFromDiscovery")
	}

	knownHosts, err := a.store.getKnownHosts()
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
			err := a.store.addHostChanges(host, rec)
			if err != nil {
				return errors.Wrap(err, "updateStoreFromDiscovery")
			}
		}
		l := log.New("host", host.hostport, "version", host.version, "fp", host.keyfp)
		if !existing || needUpdate {
			err = a.store.addOrUpdateHost(host)
			if err != nil {
				return errors.Wrap(err, "updateStoreFromDiscovery")
			}
		}
		//If it already existed and we didn't otherwise update it, mark that it was seen
		if existing {
			err = a.store.setLastSeen(host)
			if err != nil {
				return errors.Wrap(err, "updateStoreFromDiscovery")
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

func (a *SSHAuditor) updateQueues() error {
	queued, err := a.store.initHostCreds()
	if err != nil {
		return err
	}
	queuesize, err := a.store.getScanQueueSize()
	if err != nil {
		return err
	}
	log.Info("brute force queue size", "new", queued, "total", queuesize)
	return nil
}

func (a *SSHAuditor) Discover(cfg ScanConfiguration) error {
	//Push all candidate hosts into the banner fetcher queue
	hostChan, err := expandScanConfiguration(cfg)
	if err != nil {
		return err
	}

	portResults := bannerFetcher(cfg.Concurrency*2, hostChan)
	keyResults := fingerPrintFetcher(cfg.Concurrency, portResults)

	err = a.updateStoreFromDiscovery(keyResults)
	if err != nil {
		return err
	}

	err = a.updateQueues()
	return err
}

func (a *SSHAuditor) brute(scantype string, cfg ScanConfiguration) (AuditResult, error) {
	var res AuditResult
	a.updateQueues()
	var err error

	var sc []ScanRequest
	switch scantype {
	case "scan":
		sc, err = a.store.getScanQueue()
	case "rescan":
		sc, err = a.store.getRescanQueue()
	}
	if err != nil {
		return res, errors.Wrap(err, "Error getting scan queue")
	}
	_, err = a.store.Begin()
	defer a.store.Commit()
	if err != nil {
		return res, errors.Wrap(err, "brute")
	}

	bruteChan := make(chan ScanRequest, 1024)
	go func() {
		for _, sr := range sc {
			bruteChan <- sr
		}
		close(bruteChan)
	}()

	bruteResults := bruteForcer(cfg.Concurrency, bruteChan)

	var totalCount, errCount, negCount, posCount int
	for br := range bruteResults {
		l := log.New(
			"host", br.hostport,
			"user", br.cred.User,
			"password", br.cred.Password,
			"result", br.result,
		)
		if br.err != nil {
			l.Error("brute force error", "err", br.err.Error())
			errCount++
		} else if br.result == "" {
			l.Debug("negative brute force result")
			negCount++
		} else {
			l.Info("positive brute force result")
			posCount++
		}
		err = a.store.updateBruteResult(br)
		if err != nil {
			return res, err
		}
		totalCount++
	}
	log.Info("brute force scan report", "total", totalCount, "neg", negCount, "pos", posCount, "err", errCount)
	return AuditResult{
		totalCount: totalCount,
		negCount:   negCount,
		posCount:   posCount,
		errCount:   errCount,
	}, nil
}

func (a *SSHAuditor) Scan(cfg ScanConfiguration) (AuditResult, error) {
	return a.brute("scan", cfg)
}
func (a *SSHAuditor) Rescan(cfg ScanConfiguration) (AuditResult, error) {
	return a.brute("rescan", cfg)
}

func (a *SSHAuditor) Dupes() (map[string][]Host, error) {
	//FIXME: return DATA here
	return a.store.DuplicateKeyReport()
}

func (a *SSHAuditor) Logcheck(cfg ScanConfiguration) error {
	sc, err := a.store.getLogCheckQueue()
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

	bruteResults := bruteForcer(cfg.Concurrency, bruteChan)

	for br := range bruteResults {
		l := log.New("host", br.hostport, "user", br.cred.User)
		if br.err != nil {
			l.Error("Failed to send logcheck auth request", "error", br.err)
			continue
		}
		l.Info("Sent logcheck auth request")
		//TODO Collect hostports and return them for syslog cross referencing
	}
	return nil
}

func (a *SSHAuditor) LogcheckReport(ls LogSearcher) error {
	activeHosts, err := a.store.GetActiveHosts()
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

func (a *SSHAuditor) Vulnerabilities() error {
	vulns, err := a.store.GetVulnerabilities()
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
