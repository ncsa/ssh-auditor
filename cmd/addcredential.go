package cmd

import (
	"os"

	log "github.com/inconshreveable/log15"

	"github.com/ncsa/ssh-auditor/sshauditor"
	"github.com/spf13/cobra"
)

var scanIntervalDays int

var addcredentialCmd = &cobra.Command{
	Use:     "addcredential",
	Aliases: []string{"ac"},
	Short:   "add a new credential pair",
	Example: "addcredential root root123",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) != 2 {
			cmd.Usage()
			return
		}
		cred := sshauditor.Credential{
			User:         args[0],
			Password:     args[1],
			ScanInterval: scanIntervalDays,
		}
		l := log.New("user", cred.User, "password", cred.Password, "interval", scanIntervalDays)
		added, err := store.AddCredential(cred)
		if err != nil {
			log.Error(err.Error())
			os.Exit(1)
		}
		if added {
			l.Info("added credential")
		} else {
			l.Info("updated credential")
		}
	},
}

func init() {
	addcredentialCmd.Flags().IntVar(&scanIntervalDays, "scan-interval", 14, "How often to re-scan for this credential, in days")
	RootCmd.AddCommand(addcredentialCmd)
}
