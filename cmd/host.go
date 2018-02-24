package cmd

import (
	"encoding/csv"
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
		w := csv.NewWriter(os.Stdout)
		for _, c := range hosts {
			record := []string{c.Hostport, c.Version, c.Fingerprint, c.SeenFirst, c.SeenLast}
			if err := w.Write(record); err != nil {
				panic(err)
			}
		}
		w.Flush()

		if err := w.Error(); err != nil {
			panic(err)
		}
	},
}

func init() {
	RootCmd.AddCommand(hostCmd)
	hostCmd.AddCommand(hostListCmd)
	hostListCmd.Flags().IntVar(&hostMaxAgeDays, "max-age-days", 14, "List hosts seen at most this many days ago")
}
