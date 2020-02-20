package sshauditor

import (
	"fmt"
	"io/ioutil"
	"log"
	"testing"
)

type authTestCase struct {
	hostport string
	user     string
	password string
	expected string
	wanterr  bool
}

var authTestCases = []authTestCase{
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
	{
		"alpine-sshd-test-blank:22",
		"test",
		"",
		"exec",
		false,
	},
	{
		"alpine-sshd-test-test-no-id-binary:22",
		"test",
		"test",
		"tunnel",
		false,
	},
	{
		"alpine-sshd-test-test-no-id-binary-tunnel-local:22",
		"test",
		"test",
		"tunnel",
		false,
	},
	{
		"alpine-sshd-test-test-no-id-binary-no-tunnel:22",
		"test",
		"test",
		"auth",
		false,
	},
}

func init() {
	key, err := ioutil.ReadFile("../testing/docker/alpine-sshd-test-key/test.key")
	if err != nil {
		log.Printf("Can't read test key: %v", err)
		return
	}
	//log.Printf("Using key %v", key)
	authTestCases = append(authTestCases, authTestCase{
		hostport: "alpine-sshd-test-key:22",
		user:     "test",
		password: string(key),
		expected: "exec",
		wanterr:  false,
	})
}

func TestSSHAuthAttempt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	}
	for _, tt := range authTestCases {
		t.Run(fmt.Sprintf("SSHAuthAttempt(%q, %q, %q) => %q", tt.hostport, tt.user, tt.password, tt.expected), func(t *testing.T) {
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
