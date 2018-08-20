package cmd

import (
	"os"

	log "github.com/inconshreveable/log15"
	"github.com/ncsa/ssh-auditor/sshauditor"
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan hosts using new or outdated credentials",
	Run: func(cmd *cobra.Command, args []string) {
		scanConfig := sshauditor.ScanConfiguration{
			Concurrency: concurrency,
		}
		auditor := sshauditor.New(store)
		_, err := auditor.Scan(scanConfig)
		if err != nil {
			log.Error(err.Error())
			os.Exit(1)
		}
	},
}

var scanResetIntervalCmd = &cobra.Command{
	Use:     "reset",
	Aliases: []string{"r"},
	Short:   "reset interval",
	Run: func(cmd *cobra.Command, args []string) {
		err := store.ResetInterval()
		if err != nil {
			log.Error(err.Error())
			os.Exit(1)
		}
	},
}

func init() {
	RootCmd.AddCommand(scanCmd)
	scanCmd.AddCommand(scanResetIntervalCmd)
}
