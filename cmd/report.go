package cmd

import (
	"encoding/json"
	html_template "html/template"
	"os"
	text_template "text/template"

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
		if err != nil {
			log.Error(err.Error())
			os.Exit(1)
		}
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
		t := text_template.Must(text_template.New("report").Parse(reportTXTTemplate))
		err = t.Execute(os.Stdout, report)
		if err != nil {
			log.Error(err.Error())
			os.Exit(1)
		}
		return
	},
}
var reportHTMLCmd = &cobra.Command{
	Use:   "html",
	Short: "html report",
	Run: func(cmd *cobra.Command, args []string) {
		auditor := sshauditor.New(store)
		report, err := auditor.GetReport()
		if err != nil {
			log.Error(err.Error())
			os.Exit(1)
		}
		t := html_template.Must(html_template.New("report").Parse(reportHTMLTemplate))
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
	reportCmd.AddCommand(reportJSONCmd)
	reportCmd.AddCommand(reportTXTCmd)
	reportCmd.AddCommand(reportHTMLCmd)
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

var reportHTMLTemplate = `
<html>
<body>

<h1>Vulnerabilities: {{ .VulnerabilitiesCount }}</h1>
<table>
<thead>
	<tr>
		<th>Host</th>
		<th>User</th>
		<th>Password</th>
		<th>Result</th>
		<th>Last Tested</th>
		<th>Version</th>
	</tr>
</thead>
<tbody>
{{range .Vulnerabilities}}
<tr>
	<td> {{.Host.Hostport}} </td>
	<td> {{.HostCredential.User}} </td>
	<td> {{.HostCredential.Password}} </td>
	<td> {{.HostCredential.Result}} </td>
	<td> {{.HostCredential.LastTested}} </td>
	<td> {{.Host.Version}} </td>
</tr>
{{end}}
</tbody>
</table>

<h1>Duplicate Keys: {{ .DuplicateKeysCount }} </h1>
{{ range $key, $hosts := .DuplicateKeys }}
<h2> {{$key}} </h2>
<table>
<thead>
	<tr>
		<th>Host</th>
		<th>Version</th>
		<th>Seen First</th>
		<th>Seen Last</th>
	</tr>
</thead>
<tbody>
{{ range $hosts }}
<tr>
	<td> {{.Hostport}} </td>
	<td> {{.Version}} </td>
	<td> {{.SeenFirst}} </td>
	<td> {{.SeenLast}} </td>
</tr>
{{end}}
</tbody>
</table>
{{end}}

<h1> Active Hosts: {{ .ActiveHostsCount }} </h1>
<table>
<thead>
	<tr>
		<th>Host</th>
		<th>Version</th>
		<th>Seen First</th>
		<th>Seen Last</th>
	</tr>
</thead>
<tbody>
{{ range .ActiveHosts }}
<tr>
	<td> {{.Hostport}} </td>
	<td> {{.Version}} </td>
	<td> {{.SeenFirst}} </td>
	<td> {{.SeenLast}} </td>
</tr>
{{end}}
</tbody>
</table>
`
