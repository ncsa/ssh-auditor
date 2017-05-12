package cmd

import (
	"log"

	"github.com/ncsa/ssh-auditor/sshauditor"
	"github.com/spf13/cobra"
)

var ports []int

var discoverCmd = &cobra.Command{
	Use:     "discover",
	Aliases: []string{"d"},
	Example: "discover -p 22 -p 2222 192.168.1.0/24 10.1.1.0/24",
	Short:   "discover new hosts",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			cmd.Usage()
			return
		}
		scanConfig := sshauditor.ScanConfiguration{
			Include: args,
			Exclude: []string{}, //FIXME add --exclude option
			Ports:   ports,
		}
		log.Print(scanConfig)
		sshauditor.Discover(store, scanConfig)
	},
}

func init() {
	discoverCmd.Flags().IntSliceVarP(&ports, "ports", "p", []int{22}, "ports to check during initial discovery")
	RootCmd.AddCommand(discoverCmd)
}
