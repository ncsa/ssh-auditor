package cmd

import (
	"log"

	"github.com/ncsa/ssh-auditor/sshauditor"
	"github.com/spf13/cobra"
)

var logcheckCmd = &cobra.Command{
	Use:     "logcheck",
	Short:   "trigger and report on failed ssh authentication attempts",
	Aliases: []string{"lc"},
}

var logcheckRunCmd = &cobra.Command{
	Use:   "run",
	Short: "trigger failed ssh authentication attempts",
	Long: `trigger failed ssh authentication attempts in order to verify that
		local servers are properly shipping logs to a central collector`,
	Run: func(cmd *cobra.Command, args []string) {
		sshauditor.Logcheck(store)
	},
}

var splunkHost string

var logcheckReportCmd = &cobra.Command{
	Use:     "report",
	Aliases: []string{"lc"},
	Short:   "compare syslog data to the store",
	Long: `After running logcheck, search syslog for failed login attempts in
		order to determine which hosts are properly logging to syslog`,
	Run: func(cmd *cobra.Command, args []string) {
		var ls sshauditor.LogSearcher
		if splunkHost != "" {
			ls = sshauditor.NewSplunkLogSearcher(splunkHost)
		} else {
			log.Fatal("Only --splunk supported for now")
		}
		sshauditor.LogcheckReport(store, ls)
	},
}

func init() {
	RootCmd.AddCommand(logcheckCmd)

	logcheckCmd.AddCommand(logcheckRunCmd)

	logcheckReportCmd.Flags().StringVar(&splunkHost, "splunk", "", "base url to splunk API (https://host:port)")
	logcheckCmd.AddCommand(logcheckReportCmd)
}
