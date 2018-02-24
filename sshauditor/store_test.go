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
