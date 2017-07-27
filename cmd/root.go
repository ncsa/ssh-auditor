package cmd

import (
	log "github.com/sirupsen/logrus"

	"github.com/ncsa/ssh-auditor/sshauditor"
	"github.com/spf13/cobra"
)

var store *sshauditor.SQLiteStore
var dbPath string

func initStore() error {
	s, err := sshauditor.NewSQLiteStore(dbPath)
	if err != nil {
		log.Fatal(err)
	}
	err = s.Init()
	if err != nil {
		log.Fatal(err)
	}
	_, err = s.Begin()
	store = s
	return err
}

var RootCmd = &cobra.Command{
	Use:   "ssh-auditor",
	Short: "ssh-auditor tests ssh server password security",
	Long:  `Complete documentation is available at https://github.com/ncsa/ssh-auditor`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		return initStore()
	},
	PersistentPostRunE: func(cmd *cobra.Command, args []string) error {
		return store.Commit()
	},
}

func init() {
	RootCmd.PersistentFlags().StringVar(&dbPath, "db", "ssh_db.sqlite", "Path to database file")
}
