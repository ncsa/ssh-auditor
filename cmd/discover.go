package cmd

import (
	"bufio"
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
			Concurrency: concurrency,
			Include:     args,
			Exclude:     exclude,
			Ports:       ports,
		}
		auditor := sshauditor.New(store)
		err := auditor.Discover(scanConfig)
		if err != nil {
			log.Error(err.Error())
			os.Exit(1)
		}
	},
}

var discoverFromFileCmd = &cobra.Command{
	Use:     "fromfile",
	Example: "fromfile -p 22 hosts.txt",
	Short:   "discover new hosts using a list of hosts from stdin",
	Run: func(cmd *cobra.Command, args []string) {
		scanner := bufio.NewScanner(os.Stdin)
		scanConfig := sshauditor.ScanConfiguration{
			Concurrency: concurrency,
			Include:     []string{},
			Ports:       ports,
		}
		for scanner.Scan() {
			host := scanner.Text()
			scanConfig.Include = append(scanConfig.Include, host)
		}
		auditor := sshauditor.New(store)
		err := auditor.Discover(scanConfig)
		if err != nil {
			log.Error(err.Error())
			os.Exit(1)
		}
	},
}

func init() {
	discoverCmd.Flags().IntSliceVarP(&ports, "ports", "p", []int{22}, "ports to check during initial discovery")
	discoverCmd.Flags().StringSliceVarP(&exclude, "exclude", "x", []string{}, "subnets to exclude from discovery")

	discoverFromFileCmd.Flags().IntSliceVarP(&ports, "ports", "p", []int{22}, "ports to check during initial discovery")
	RootCmd.AddCommand(discoverCmd)
	discoverCmd.AddCommand(discoverFromFileCmd)
}
