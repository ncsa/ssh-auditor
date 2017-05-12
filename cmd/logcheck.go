package cmd

import (
	"github.com/ncsa/ssh-auditor/sshauditor"
	"github.com/spf13/cobra"
)

var logcheckCmd = &cobra.Command{
	Use:     "logcheck",
	Aliases: []string{"lc"},
	Short:   "trigger failed ssh authentication attempts",
	Long: `trigger failed ssh authentication attempts in order to verify that
		local servers are properly shipping logs to a central collector`,
	Run: func(cmd *cobra.Command, args []string) {
		sshauditor.Logcheck(store)
	},
}

func init() {
	RootCmd.AddCommand(logcheckCmd)
}
