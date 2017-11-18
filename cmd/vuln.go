package cmd

import (
	"os"

	"github.com/ncsa/ssh-auditor/sshauditor"
	"github.com/prometheus/common/log"
	"github.com/spf13/cobra"
)

var vulnCmd = &cobra.Command{
	Use:   "vuln",
	Short: "Show vulnerabilities",
	Run: func(cmd *cobra.Command, args []string) {
		auditor := sshauditor.New(store)
		err := auditor.Vulnerabilities()
		if err != nil {
			log.Error(err.Error())
			os.Exit(1)
		}
	},
}

func init() {
	RootCmd.AddCommand(vulnCmd)
}
