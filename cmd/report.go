package cmd

import (
	"encoding/json"
	"html/template"
	"os"

	log "github.com/inconshreveable/log15"
	"github.com/ncsa/ssh-auditor/sshauditor"

	"github.com/spf13/cobra"
)

var reportCmd = &cobra.Command{
	Use:     "report",
	Short:   "output a full audit report",
	Aliases: []string{"rep"},
}

var reportJSONCmd = &cobra.Command{
	Use:   "json",
	Short: "json report",
	Run: func(cmd *cobra.Command, args []string) {
		auditor := sshauditor.New(store)
		report, err := auditor.GetReport()
		w := json.NewEncoder(os.Stdout)
		w.SetIndent("", "  ")
		err = w.Encode(report)
		if err != nil {
			log.Error(err.Error())
			os.Exit(1)
		}
	},
}

var reportTXTCmd = &cobra.Command{
	Use:   "txt",
	Short: "plain text report",
	Run: func(cmd *cobra.Command, args []string) {
		auditor := sshauditor.New(store)
		report, err := auditor.GetReport()
		if err != nil {
			log.Error(err.Error())
			os.Exit(1)
		}
		t := template.Must(template.New("report").Parse(reportTXTTemplate))
		err = t.Execute(os.Stdout, report)
		if err != nil {
			log.Error(err.Error())
			os.Exit(1)
		}
		return
	},
}

func init() {
	RootCmd.AddCommand(reportCmd)
	reportCmd.AddCommand(reportTXTCmd)
	reportCmd.AddCommand(reportJSONCmd)
}

var reportTXTTemplate = `
Vulnerabilities: {{ .VulnerabilitiesCount }} 
{{range .Vulnerabilities}}
	Host {{.Host.Hostport}}
	Version {{.Host.Version}}
	User {{.HostCredential.User}}
	Password {{.HostCredential.Password}}
	Result {{.HostCredential.Result}}
	Last Tested {{.HostCredential.LastTested}}
{{end}}

Duplicate Keys: {{ .DuplicateKeysCount }} 
{{ range $key, $hosts := .DuplicateKeys }}
{{$key}}:
{{ range $hosts }}
	Host {{.Hostport}}
	Version {{.Version}}
	Seen First {{.SeenFirst}}
	Seen Last {{.SeenLast}}
{{end}}
{{end}}

Active Hosts: {{ .ActiveHostsCount }}
{{ range .ActiveHosts }}
	Host {{.Hostport}}
	Version {{.Version}}
	Seen First {{.SeenFirst}}
	Seen Last {{.SeenLast}}
{{end}}
`
