package cmd

import (
	"fmt"
	"os"

	"github.com/ncsa/ssh-auditor/sshauditor"
	"github.com/prometheus/common/log"
	"github.com/spf13/cobra"
)

var dupesCmd = &cobra.Command{
	Use:   "dupes",
	Short: "Show hosts using the same key",
	Run: func(cmd *cobra.Command, args []string) {
		auditor := sshauditor.New(store)
		keyMap, err := auditor.Dupes()
		if err != nil {
			log.Error(err.Error())
			os.Exit(1)
		}
		for fp, hosts := range keyMap {
			fmt.Printf("Key %s in use by %d hosts:\n", fp, len(hosts))
			for _, h := range hosts {
				fmt.Printf(" %s\t%s\t%s\t%s\n", h.Hostport, h.SeenFirst, h.SeenLast, h.Version)
			}
			fmt.Println()
		}
		return
	},
}

func init() {
	RootCmd.AddCommand(dupesCmd)
}
