package sshauditor

import (
	"fmt"
	"testing"
)

var authTestCases = []struct {
	hostport string
	user     string
	password string
	expected string
	wanterr  bool
}{
	{
		"alpine-sshd-ok:22",
		"root",
		"test",
		"",
		false,
	},
	{
		"alpine-sshd-test-test:22",
		"test",
		"test",
		"exec",
		false,
	},
}

func TestSSHAuthAttempt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	}
	for _, tt := range authTestCases {
		t.Run(fmt.Sprintf("SSHAuthAttempt(%q, %q, %q)", tt.hostport, tt.user, tt.password), func(t *testing.T) {
			resp, err := SSHAuthAttempt(tt.hostport, tt.user, tt.password)
			if err != nil && tt.wanterr != true {
				t.Errorf("Unexpected error %v", err)
			}
			if err == nil && tt.wanterr == true {
				t.Errorf("did not return an expected error")
			}
			if resp != tt.expected {
				t.Errorf("got %#v, want %#v", resp, tt.expected)
			}
		})
	}
}
