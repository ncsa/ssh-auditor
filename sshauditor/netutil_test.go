package sshauditor

import "testing"

var testCases = []struct {
	include   []string
	exclude   []string
	expected  int
	wanterror bool
}{
	{[]string{"192.168.1.0/24"}, []string{}, 256, false},
	{[]string{"192.168.1.0/24"}, []string{"192.168.1.30/32"}, 255, false},
	{[]string{"192.168.1.0/24"}, []string{"192.168.1.30/30"}, 252, false},
	{[]string{"192.168.1.0/33"}, []string{}, 0, true},
}

func TestEnumerateHosts(t *testing.T) {
	for _, tt := range testCases {
		hosts, err := EnumerateHosts(tt.include, tt.exclude)
		if err != nil && tt.wanterror != true {
			t.Error(err)
		}
		if err == nil && tt.wanterror == true {
			t.Errorf("EnumerateHosts(%#v, %#v) did not return an error", tt.include, tt.exclude)
		}
		if len(hosts) != tt.expected {
			t.Errorf("EnumerateHosts(%#v, %#v) => len(hosts) is %#v, want %#v", tt.include, tt.exclude, len(hosts), tt.expected)
		}
	}
}
