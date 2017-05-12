package cmd

import (
	"github.com/ncsa/ssh-auditor/sshauditor"
	"github.com/spf13/cobra"
)

var rescanCmd = &cobra.Command{
	Use:   "rescan",
	Short: "Rescan hosts with credentials that have previously worked",
	Run: func(cmd *cobra.Command, args []string) {
		sshauditor.Rescan(store)
	},
}

func init() {
	RootCmd.AddCommand(rescanCmd)
}
