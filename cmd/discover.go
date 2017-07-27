package cmd

import (
	"os"

	log "github.com/inconshreveable/log15"
	"github.com/ncsa/ssh-auditor/sshauditor"
	"github.com/spf13/cobra"
)

var ports []int
var exclude []string

var discoverCmd = &cobra.Command{
	Use:     "discover",
	Aliases: []string{"d"},
	Example: "discover -p 22 -p 2222 192.168.1.0/24 10.1.1.0/24 --exclude 192.168.1.100/32",
	Short:   "discover new hosts",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			cmd.Usage()
			return
		}
		scanConfig := sshauditor.ScanConfiguration{
			Include: args,
			Exclude: exclude,
			Ports:   ports,
		}
		err := sshauditor.Discover(store, scanConfig)
		if err != nil {
			log.Error(err.Error())
			os.Exit(1)
		}
	},
}

func init() {
	discoverCmd.Flags().IntSliceVarP(&ports, "ports", "p", []int{22}, "ports to check during initial discovery")
	discoverCmd.Flags().StringSliceVarP(&exclude, "exclude", "x", []string{}, "subnets to exclude from discovery")
	RootCmd.AddCommand(discoverCmd)
}
