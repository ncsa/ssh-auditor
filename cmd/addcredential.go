package cmd

import (
	"encoding/json"
	"os"

	log "github.com/inconshreveable/log15"

	"github.com/ncsa/ssh-auditor/sshauditor"
	"github.com/spf13/cobra"
)

var credentialCmd = &cobra.Command{
	Use:     "credential",
	Short:   "manage credentials",
	Aliases: []string{"cred", "c"},
}

var scanIntervalDays int

var credentialAddCmd = &cobra.Command{
	Use:     "add",
	Aliases: []string{"addcredential", "ac", "add"},
	Short:   "add a new credential pair",
	Example: "add root root123",
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
var credentialListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"l"},
	Short:   "list credentials",
	Run: func(cmd *cobra.Command, args []string) {
		creds, err := store.GetAllCreds()
		if err != nil {
			log.Error(err.Error())
			os.Exit(1)
		}
		w := json.NewEncoder(os.Stdout)
		for _, c := range creds {
			if err := w.Encode(c); err != nil {
				panic(err)
			}
		}
	},
}

func init() {
	credentialAddCmd.Flags().IntVar(&scanIntervalDays, "scan-interval", 14, "How often to re-scan for this credential, in days")
	RootCmd.AddCommand(credentialAddCmd)
	RootCmd.AddCommand(credentialCmd)
	credentialCmd.AddCommand(credentialAddCmd)
	credentialCmd.AddCommand(credentialListCmd)
}
