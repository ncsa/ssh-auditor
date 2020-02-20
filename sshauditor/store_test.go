package sshauditor

import (
	"testing"
)

func TestAddCredential(t *testing.T) {
	check := func(e error) {
		if e != nil {
			t.Fatal(e)
		}
	}
	s, err := NewSQLiteStore(":memory:")
	check(err)
	err = s.Init()
	check(err)
	cred := Credential{User: "foo", Password: "foo", ScanInterval: 5}

	added, err := s.AddCredential(cred)
	check(err)
	if added != true {
		t.Errorf("Expected added to be true")
	}

	creds, err := s.GetAllCreds()
	check(err)
	if len(creds) != 1 {
		t.Errorf("Expected 1 cred, got %d", len(creds))
	}
	if creds[0] != cred {
		t.Errorf("Expected %v, got %v", cred, creds[0])
	}

	cred = Credential{User: "foo", Password: "foo", ScanInterval: 10}
	added, err = s.AddCredential(cred)
	check(err)
	if added != false {
		t.Errorf("Expected added to be false")
	}
	creds, err = s.GetAllCreds()
	check(err)
	if len(creds) != 1 {
		t.Errorf("Expected 1 cred, got %d", len(creds))
	}
	if creds[0] != cred {
		t.Errorf("Expected %q, got %q", cred, creds[0])
	}

}

func TestAddAndDeleteHost(t *testing.T) {
	check := func(e error) {
		if e != nil {
			t.Fatal(e)
		}
	}
	s, err := NewSQLiteStore(":memory:")
	check(err)
	err = s.Init()
	check(err)

	s.addOrUpdateHost(SSHHost{
		hostport: "192.168.1.1:22",
		version:  "whatever",
		keyfp:    "whatever",
	})
	knownHosts, err := s.GetActiveHosts(7)
	check(err)
	if knownHosts[0].Hostport != "192.168.1.1:22" {
		knownHosts, err := s.GetActiveHosts(7)
		check(err)
		if len(knownHosts) != 1 {
			t.Fatalf("Expected 1 host, got %d", len(knownHosts))
		}
		t.Fatalf("Expected 192.168.1.1:22 , got %s", knownHosts[0].Hostport)
	}

	err = s.DeleteHost("192.168.1.1:22")
	check(err)
	knownHosts, err = s.GetActiveHosts(7)
	check(err)
	if len(knownHosts) != 0 {
		t.Fatalf("Expected 0 hosts, got %d", len(knownHosts))
	}
}
