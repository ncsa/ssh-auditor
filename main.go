package main

import (
	"os"

	log "github.com/inconshreveable/log15"
	"github.com/ncsa/ssh-auditor/cmd"
)

func main() {
	if err := cmd.RootCmd.Execute(); err != nil {
		if err != nil {
			log.Error(err.Error())
			os.Exit(1)
		}
	}
}
