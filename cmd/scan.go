package cmd

import (
	"github.com/ncsa/ssh-auditor/sshauditor"
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan hosts using new or outdated credentials",
	Run: func(cmd *cobra.Command, args []string) {
		sshauditor.Scan(store)
	},
}

func init() {
	RootCmd.AddCommand(scanCmd)
}
