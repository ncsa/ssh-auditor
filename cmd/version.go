package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	Version = "0.10"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of ssh-auditor",
	// Don't create a store
	PersistentPreRunE:  func(cmd *cobra.Command, args []string) error { return nil },
	PersistentPostRunE: func(cmd *cobra.Command, args []string) error { return nil },
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(Version)
	},
}

func init() {
	RootCmd.AddCommand(versionCmd)
}
