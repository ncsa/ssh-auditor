package cmd

import (
	"os"

	"github.com/ncsa/ssh-auditor/sshauditor"
	"github.com/prometheus/common/log"
	"github.com/spf13/cobra"
)

var dupesCmd = &cobra.Command{
	Use:   "dupes",
	Short: "Show hosts using the same key",
	Run: func(cmd *cobra.Command, args []string) {
		err := sshauditor.Dupes(store)
		if err != nil {
			log.Error(err.Error())
			os.Exit(1)
		}
	},
}

func init() {
	RootCmd.AddCommand(dupesCmd)
}
