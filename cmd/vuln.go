package cmd

import (
	"github.com/ncsa/ssh-auditor/sshauditor"
	"github.com/spf13/cobra"
)

var vulnCmd = &cobra.Command{
	Use:   "vuln",
	Short: "Show vulnerabilities",
	Run: func(cmd *cobra.Command, args []string) {
		sshauditor.Vulnerabilities(store)
	},
}

func init() {
	RootCmd.AddCommand(vulnCmd)
}
