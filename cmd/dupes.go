package cmd

import (
	"encoding/json"
	"os"

	log "github.com/inconshreveable/log15"
	"github.com/ncsa/ssh-auditor/sshauditor"
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
		w := json.NewEncoder(os.Stdout)
		w.SetIndent("", "  ")
		err = w.Encode(keyMap)
		if err != nil {
			log.Error(err.Error())
			os.Exit(1)
		}
		return
	},
}

func init() {
	RootCmd.AddCommand(dupesCmd)
}
