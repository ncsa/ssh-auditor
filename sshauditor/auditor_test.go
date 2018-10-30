package sshauditor

import (
	"fmt"
	"net"
	"strconv"
	"testing"
)

//makeScanConfig returns a ScanConfiguration based on a single host:port
//Normally ssh-auditor deals with a list of cidr ranges and a list of ports
//so this just needs to reformat things a bit for testing purposes so
//things can be tested without knowing the ip range that docker is allocating
func makeScanConfig(hostport string) (ScanConfiguration, string, error) {
	var sc ScanConfiguration
	host, port, err := net.SplitHostPort(hostport)
	//I control the test data, so this should not happen
	if err != nil {
		return sc, "", err
	}
	ips, err := net.LookupHost(host)
	if len(ips) != 1 {
		return sc, "", fmt.Errorf("Resolving of %s failed to return a sigle ip: %#v", host, ips)
	}
	scanDestination := fmt.Sprintf("%s/32", ips[0])
	ipport := fmt.Sprintf("%s:%s", ips[0], port)
	portInt, err := strconv.Atoi(port)
	if err != nil {
		return sc, "", err
	}
	scanConfig := ScanConfiguration{
		Concurrency: 1,
		Include:     []string{scanDestination},
		Ports:       []int{portInt},
	}
	return scanConfig, ipport, nil
}

//TestSSHAuditorE2E tests the discovery, scan, and vuln process
//This re-uses the authTestCases from sshutil_test.go
func TestSSHAuditorE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	}
	for _, tt := range authTestCases {
		t.Run(fmt.Sprintf("TestSSHAuditorE2E(%q, %q, %q) => %q", tt.hostport, tt.user, tt.password, tt.expected), func(t *testing.T) {
			store, err := NewSQLiteStore(":memory:")
			if err != nil {
				t.Fatal(err)
			}
			err = store.Init()
			if err != nil {
				t.Fatal(err)
			}

			cred := Credential{
				User:         tt.user,
				Password:     tt.password,
				ScanInterval: 1,
			}
			_, err = store.AddCredential(cred)
			if err != nil {
				t.Fatal(err)
			}

			auditor := New(store)
			sc, ipport, err := makeScanConfig(tt.hostport)
			if err != nil {
				t.Fatal(err)
			}
			err = auditor.Discover(sc)
			if err != nil {
				t.Fatal(err)
			}
			ar, err := auditor.Scan(sc)
			if err != nil {
				t.Fatal(err)
			}
			if ar.totalCount != 1 {
				t.Errorf("totalCount != 1: %#v", ar.totalCount)
			}
			vulns, err := auditor.Vulnerabilities()
			if err != nil {
				t.Fatal(err)
			}

			if tt.expected != "" {
				if ar.posCount != 1 {
					t.Errorf("posCount != 1: %#v", ar.posCount)
				}
				if ar.negCount != 0 {
					t.Errorf("negCount != 0: %#v", ar.negCount)
				}
				if len(vulns) != 1 {
					t.Fatalf("len(vulns) != 1: %#v", vulns)
				}
				if vulns[0].Host.Hostport != ipport {
					t.Errorf("vuln[0].hostport != %#v: %#v", ipport, vulns)
				}
				if vulns[0].HostCredential.Result != tt.expected {
					t.Errorf("vuln[0].HostCredential.Result != %#v: %#v", tt.expected, vulns)
				}
			} else {
				if ar.posCount != 0 {
					t.Errorf("posCount != 0: %#v", ar.posCount)
				}
				if ar.negCount != 1 {
					t.Errorf("negCount != 1: %#v", ar.negCount)
				}
				if len(vulns) != 0 {
					t.Errorf("len(vulns) != 0: %#v", vulns)
				}
			}
		})
	}
}
