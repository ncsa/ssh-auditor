package cmd

import (
	"os"

	"github.com/ncsa/ssh-auditor/sshauditor"
	"github.com/prometheus/common/log"
	"github.com/spf13/cobra"
)

var rescanCmd = &cobra.Command{
	Use:   "rescan",
	Short: "Rescan hosts with credentials that have previously worked",
	Run: func(cmd *cobra.Command, args []string) {
		scanConfig := sshauditor.ScanConfiguration{
			Concurrency: concurrency,
		}
		err := sshauditor.Rescan(store, scanConfig)
		if err != nil {
			log.Error(err.Error())
			os.Exit(1)
		}
	},
}

func init() {
	RootCmd.AddCommand(rescanCmd)
}
