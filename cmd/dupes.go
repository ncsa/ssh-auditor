package cmd

import (
	"github.com/ncsa/ssh-auditor/sshauditor"
	"github.com/spf13/cobra"
)

var dupesCmd = &cobra.Command{
	Use:   "dupes",
	Short: "Show hosts using the same key",
	Run: func(cmd *cobra.Command, args []string) {
		sshauditor.Dupes(store)
	},
}

func init() {
	RootCmd.AddCommand(dupesCmd)
}
