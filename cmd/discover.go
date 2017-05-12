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
	Short:   "discover new hosts",
	Run: func(cmd *cobra.Command, args []string) {
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

/*
func oldmain() {
	flag.Parse()

	store, err := NewSQLiteStore("ssh_db.sqlite")
	if err != nil {
		log.Fatal(err)
	}
	err = store.Init()
	if err != nil {
		log.Fatal(err)
	}
	_, err = store.Begin()
	if err != nil {
		log.Fatal(err)
	}
	defer store.Commit()
	cmd := flag.Args()[0]
	args := flag.Args()[1:]

	switch cmd {
	case "addcredential":
		cred := Credential{
			User:     args[0],
			Password: args[1],
		}
		err := store.AddCredential(cred)
		if err != nil {
			log.Fatal(err)
		}
	case "discover":
		scanConfig := ScanConfiguration{
			include: args,
			exclude: []string{},
		}
		log.Print(scanConfig)

		discover(store, scanConfig)
	case "logcheck":
		logcheck(store)
	case "scan":
		brute(store, "scan")
	case "rescan":
		brute(store, "rescan")
	case "dupes":
		store.duplicateKeyReport()
	default:
		log.Fatalf("Unknown command %s", cmd)
	}
}
*/
