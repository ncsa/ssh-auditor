package main

import (
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

CREATE TABLE IF NOT EXISTS creds (
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
	for _, h := range hosts {
		hosts[h.Hostport] = h
	}
	return hosts, nil
}

func (s *SQLiteStore) addOrUpdateHost(h SSHHost) error {
	res, err := s.conn.Exec(
		"UPDATE hosts SET version=$1 fingerprint=$2 time_last=datetime('now', 'localtime')",
		h.version, h.keyfp)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if rows != 0 {
		return err
	}
	_, err = s.conn.Exec(
		`INSERT INTO hosts (hostport, version, fingerprint, time_first, time_last) VALUES
			($1, $2, $3, datetime('now', 'localtime'), datetime('now', 'localtime')`,
		h.hostport, h.version, h.keyfp)
	return err
}
