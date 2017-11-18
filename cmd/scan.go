package cmd

import (
	"os"

	"github.com/ncsa/ssh-auditor/sshauditor"
	"github.com/prometheus/common/log"
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
		err := auditor.Scan(scanConfig)
		if err != nil {
			log.Error(err.Error())
			os.Exit(1)
		}
	},
}

func init() {
	RootCmd.AddCommand(scanCmd)
}
