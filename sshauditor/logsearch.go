package sshauditor

import (
	"fmt"

	splunk "github.com/sebkl/splunk-golang"
)

type LogSearcher interface {
	GetIPs() ([]string, error)
}

type SplunkLogSearcher struct {
	conn splunk.SplunkConnection
}

func NewSplunkLogSearcher(baseURL string) LogSearcher {
	username, password := promptCredentials() //FIXME: better config?
	conn := splunk.SplunkConnection{
		Username:   username,
		SplunkUser: username, //FIXME: why is this a thing?
		Password:   password,
		SplunkApp:  "search",
		BaseURL:    baseURL,
	}
	return &SplunkLogSearcher{conn: conn}
}

func (s *SplunkLogSearcher) GetIPs() ([]string, error) {
	var ips []string
	_, err := s.conn.Login()

	if err != nil {
		return ips, err
	}

	//fmt.Println("Session key: ", key.Value)

	rows, _, err := s.conn.Search(`search daysago=2 logcheck user NOT krbtgt | rex "logcheck-(?<logcheck>[0-9.]+)" | table logcheck | dedup logcheck`)
	if err != nil {
		panic(err)
	}
	//for _, e := range events {
	//      fmt.Printf("%v\n", e)
	//}
	fmt.Printf("\n")
	for _, e := range rows {
		ip := e.Result["logcheck"].(string)
		ips = append(ips, ip)
	}
	return ips, nil
}
