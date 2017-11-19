package cmd

import (
	"fmt"
	"os"

	log "github.com/inconshreveable/log15"
	"github.com/ncsa/ssh-auditor/sshauditor"
	"github.com/spf13/cobra"
)

var vulnCmd = &cobra.Command{
	Use:   "vuln",
	Short: "Show vulnerabilities",
	Run: func(cmd *cobra.Command, args []string) {
		auditor := sshauditor.New(store)
		vulns, err := auditor.Vulnerabilities()
		if err != nil {
			log.Error(err.Error())
			os.Exit(1)
		}
		for _, v := range vulns {
			fmt.Printf("%s\t%s\t%s\t%s\t%s\t%s\n",
				v.Host.Hostport,
				v.HostCredential.User,
				v.HostCredential.Password,
				v.HostCredential.Result,
				v.HostCredential.LastTested,
				v.Host.Version,
			)
		}
	},
}

func init() {
	RootCmd.AddCommand(vulnCmd)
}
