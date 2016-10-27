package main

import (
	"log"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
)

const schema = `
CREATE TABLE IF NOT EXISTS hosts (
	hostport character varying,
	version character varying,
	fingerprint character varying,
	seen_first REAL,
	seen_last REAL,

	PRIMARY KEY (hostport)
);

CREATE TABLE IF NOT EXISTS credentials (
	user character varying,
	password character varying,
	priority DEFAULT 0,

	PRIMARY KEY (user, password)
);

CREATE TABLE IF NOT EXISTS host_creds (
	hostport character varying,
	user character varying,
	password character varying,
	last_tested REAL,
	result boolean,
	priority DEFAULT 0,

	PRIMARY KEY (hostport, user, password)
);

CREATE TABLE IF NOT EXISTS host_changes (
	hostport character varying,
	message character varying
)
`

type Host struct {
	Hostport    string
	Version     string
	Fingerprint string
	SeenFirst   string `db:"seen_first"`
	SeenLast    string `db:"seen_last"`
}

type Credential struct {
	User     string
	Password string
	Priority int
}

type HostCredential struct {
	Hostport   string
	User       string
	Password   string
	LastTested string `db:"last_tested"`
	Result     bool
	Priority   int
}

type SQLiteStore struct {
	conn *sqlx.DB
}

func NewSQLiteStore(uri string) (*SQLiteStore, error) {
	conn, err := sqlx.Open("sqlite3", uri)
	if err != nil {
		return nil, err
	}
	return &SQLiteStore{conn: conn}, nil
}

func (s *SQLiteStore) Close() error {
	return s.conn.Close()
}

func (s *SQLiteStore) Init() error {
	_, err := s.conn.Exec(schema)
	return err
}

func (s *SQLiteStore) getKnownHosts() (map[string]Host, error) {
	hostList := []Host{}

	hosts := make(map[string]Host)

	err := s.conn.Select(&hostList, "SELECT * FROM hosts")
	if err != nil {
		return hosts, err
	}
	for _, h := range hostList {
		hosts[h.Hostport] = h
	}
	return hosts, nil
}

func (s *SQLiteStore) resetHostCreds(h SSHHost) error {
	_, err := s.conn.Exec("UPDATE host_creds set last_tested=0 where hostport=$1", h.hostport)
	return err
}

func (s *SQLiteStore) addOrUpdateHost(h SSHHost) error {
	err := s.resetHostCreds(h)
	if err != nil {
		return err
	}
	res, err := s.conn.Exec(
		`UPDATE hosts SET version=$1,fingerprint=$2,seen_last=datetime('now', 'localtime')
			WHERE hostport=$3`,
		h.version, h.keyfp, h.hostport)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if rows != 0 {
		return err
	}
	_, err = s.conn.Exec(
		`INSERT INTO hosts (hostport, version, fingerprint, seen_first, seen_last) VALUES
			($1, $2, $3, datetime('now', 'localtime'), datetime('now', 'localtime'))`,
		h.hostport, h.version, h.keyfp)
	return err
}

func (s *SQLiteStore) getAllCreds() ([]Credential, error) {
	credentials := []Credential{}
	err := s.conn.Select(&credentials, "SELECT * from credentials")
	return credentials, err
}

func (s *SQLiteStore) initHostCreds() (int, error) {
	creds, err := s.getAllCreds()
	if err != nil {
		return 0, err
	}

	knownHosts, err := s.getKnownHosts()
	if err != nil {
		return 0, err
	}

	inserted := 0
	for _, host := range knownHosts {
		ins, err := s.initHostCredsForHost(creds, host)
		if err != nil {
			return inserted, err
		}
		inserted += ins
	}
	return inserted, nil
}
func (s *SQLiteStore) initHostCredsForHost(creds []Credential, h Host) (int, error) {
	inserted := 0
	for _, c := range creds {
		res, err := s.conn.Exec(`INSERT OR IGNORE INTO host_creds (hostport, user, password, last_tested, result, priority) VALUES
			($1, $2, $3, 0, 0, $4)`,
			h.Hostport, c.User, c.Password, c.Priority)
		if err != nil {
			return inserted, err
		}
		rows, err := res.RowsAffected()
		inserted += int(rows)
	}
	return inserted, nil
}

func (s *SQLiteStore) getScanQueue() ([]ScanRequest, error) {

	requestMap := make(map[string]*ScanRequest)
	var requests []ScanRequest
	q := `select * from host_creds where last_tested < datetime('now', '-1 day') order by last_tested ASC limit 100`
	credentials := []HostCredential{}
	err := s.conn.Select(&credentials, q)
	if err != nil {
		return requests, err
	}

	for _, hc := range credentials {
		sr := requestMap[hc.Hostport]
		if sr == nil {
			sr = &ScanRequest{
				host: Host{Hostport: hc.Hostport},
			}
		}
		sr.credentials = append(sr.credentials, Credential{User: hc.User, Password: hc.Password})
		requestMap[hc.Hostport] = sr
	}

	for _, sr := range requestMap {
		requests = append(requests, *sr)
	}

	return requests, nil
}

func (s *SQLiteStore) updateBruteResult(br BruteForceResult) error {
	log.Printf("Result %s %v %v", br.host.Hostport, br.cred, br.success)
	_, err := s.conn.Exec(`UPDATE host_creds set last_tested=datetime('now', 'localtime'), result=$2
		WHERE hostport=$1 AND user=$3 AND password=$4`,
		br.host.Hostport, br.success, br.cred.User, br.cred.Password)
	return err
}
