package main

import (
	"os"

	"github.com/ncsa/ssh-auditor/cmd"
	"github.com/prometheus/common/log"
)

func main() {

	if err := cmd.RootCmd.Execute(); err != nil {
		if err != nil {
			log.Error(err.Error())
			os.Exit(1)
		}
	}
}
