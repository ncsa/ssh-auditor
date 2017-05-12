package sshauditor

import "net"

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func EnumerateHosts(netblocks []string, exclude []string) ([]string, error) {
	var hosts []string
	excludeHosts := make(map[string]bool)
	for _, netblock := range exclude {
		ip, ipnet, err := net.ParseCIDR(netblock)
		if err != nil {
			return hosts, err
		}

		for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
			excludeHosts[ip.String()] = true
		}
	}

	for _, netblock := range netblocks {
		ip, ipnet, err := net.ParseCIDR(netblock)
		if err != nil {
			return hosts, err
		}
		for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
			if _, excluded := excludeHosts[ip.String()]; !excluded {
				hosts = append(hosts, ip.String())
			}
		}
	}
	return hosts, nil
}
