package cmd

import (
	"encoding/json"
	"os"

	log "github.com/inconshreveable/log15"

	"github.com/spf13/cobra"
)

var hostCmd = &cobra.Command{
	Use:     "host",
	Short:   "manage hosts",
	Aliases: []string{"host", "h"},
}

var hostMaxAgeDays int

var hostListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"l"},
	Short:   "list hosts",
	Run: func(cmd *cobra.Command, args []string) {
		hosts, err := store.GetActiveHosts(hostMaxAgeDays)
		if err != nil {
			log.Error(err.Error())
			os.Exit(1)
		}
		w := json.NewEncoder(os.Stdout)
		for _, c := range hosts {
			if err := w.Encode(c); err != nil {
				panic(err)
			}
		}
	},
}

var hostDeleteCmd = &cobra.Command{
	Use:     "delete",
	Aliases: []string{"r"},
	Short:   "delete hosts",
	Run: func(cmd *cobra.Command, args []string) {
		for _, host := range args {
			err := store.DeleteHost(host)
			if err != nil {
				log.Error(err.Error())
				os.Exit(1)
			}
		}
	},
}

func init() {
	RootCmd.AddCommand(hostCmd)
	hostCmd.AddCommand(hostListCmd)
	hostListCmd.Flags().IntVar(&hostMaxAgeDays, "max-age-days", 14, "List hosts seen at most this many days ago")
	hostCmd.AddCommand(hostDeleteCmd)
}
