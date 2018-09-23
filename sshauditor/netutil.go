package sshauditor

import (
	"net"
	"strings"
)

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func ExpandCIDRs(netblocks []string) ([]string, error) {
	var hosts []string
	for _, netblock := range netblocks {
		//If there's no slash, just treat as a single host
		if !strings.ContainsRune(netblock, '/') {
			hosts = append(hosts, netblock)
			continue
		}
		ip, ipnet, err := net.ParseCIDR(netblock)
		if err != nil {
			return hosts, err
		}
		for h := ip.Mask(ipnet.Mask); ipnet.Contains(h); inc(h) {
			hosts = append(hosts, h.String())
		}
	}
	return hosts, nil
}

func EnumerateHosts(netblocks []string, exclude []string) ([]string, error) {
	var hosts []string
	allHosts, err := ExpandCIDRs(netblocks)
	if err != nil {
		return hosts, err
	}

	allExcludeHosts, err := ExpandCIDRs(exclude)
	if err != nil {
		return hosts, err
	}
	excludeHosts := make(map[string]bool)
	for _, ip := range allExcludeHosts {
		excludeHosts[ip] = true
	}

	for _, ip := range allHosts {
		if _, excluded := excludeHosts[ip]; !excluded {
			hosts = append(hosts, ip)
		}
	}
	return hosts, nil
}
