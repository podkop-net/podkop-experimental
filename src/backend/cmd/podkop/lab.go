//go:build lab

package main

// The commands of the lab: each step of the backend by hand, to compare and to time it.
// A product build leaves them out; the lab builds with the tag lab.

import (
	"context"
	"encoding/json"
	"io"
	"os"

	"github.com/podkop-net/podkop-experimental/src/backend/ctl"
	"github.com/podkop-net/podkop-experimental/src/backend/diag"
	"github.com/podkop-net/podkop-experimental/src/backend/dnsmasq"
	"github.com/podkop-net/podkop-experimental/src/backend/model"
	"github.com/podkop-net/podkop-experimental/src/backend/plan"
	"github.com/podkop-net/podkop-experimental/src/backend/render"
	"github.com/podkop-net/podkop-experimental/src/backend/uci"
	"github.com/sagernet/sing-box/common/sharelink"
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/spf13/cobra"
)

var (
	commandRenderFlagUCI        string
	commandRenderFlagOutput     string
	commandRenderFlagRuleSetDir string
	commandRenderFlagRoot       string
	commandRenderFlagLANAddress string
	commandRenderFlagNoCheck    bool
)

var commandRender = &cobra.Command{
	Use:   "render",
	Short: "Write the sing-box configuration and the rule-set files of the settings",
	Long: "Write the sing-box configuration and the rule-set files of the settings.\n\n" +
		"Nothing else is touched: no firewall rule, no service. The configuration is built\n" +
		"by sing-box before it is stored, and one that does not pass is not stored.\n\n" +
		"Exit status:\n" +
		"  0  the files are written; lines \"warning: ...\" on the standard error name what\n" +
		"     was skipped\n" +
		"  2  the settings cannot be used; a line \"error: ...\" on the standard error says why\n" +
		"  1  anything else",
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(renderSettings(os.Stdout, os.Stderr))
	},
}

func init() {
	commandRender.Flags().StringVar(&commandRenderFlagUCI, "uci", "/etc/config/podkop", "The settings file")
	commandRender.Flags().StringVar(&commandRenderFlagOutput, "output", "/tmp/podkop-render/config.json", "Where the configuration goes")
	commandRender.Flags().StringVar(&commandRenderFlagRuleSetDir, "rule-set-dir", "", "Where the rule-set files go (default "+plan.DefaultRuleSetDir+")")
	commandRender.Flags().StringVar(&commandRenderFlagRoot, "root", "", "A directory put before every path read or written, the settings file excepted")
	commandRender.Flags().StringVar(&commandRenderFlagLANAddress, "lan-address", "", "The IPv4 address of the LAN, for the services that listen there")
	commandRender.Flags().BoolVar(&commandRenderFlagNoCheck, "no-check", false, "Do not build the configuration before it is stored")
	mainCommand.AddCommand(commandRender)
}

var (
	commandCheckDNSFlagUCI  string
	commandCheckDNSFlagDHCP string
)

var commandCheckDNS = &cobra.Command{
	Use:   "check-dns",
	Short: "Ask the DNS servers of the settings and the resolver of the router, and print what answered",
	Long: "Ask the DNS server of the settings, the resolver of the router and the bootstrap\n" +
		"server for a name, from the router itself, and tell whether dnsmasq is set up to ask\n" +
		"the backend. The answer is the JSON object the check_dns_available command of podkop\n" +
		"prints.",
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(checkDNS(os.Stdout, os.Stderr))
	},
}

func init() {
	commandCheckDNS.Flags().StringVar(&commandCheckDNSFlagUCI, "uci", "/etc/config/podkop", "The settings file")
	commandCheckDNS.Flags().StringVar(&commandCheckDNSFlagDHCP, "dhcp", "/etc/config/dhcp", "The settings file of dnsmasq")
	mainCommand.AddCommand(commandCheckDNS)
}

func checkDNS(output io.Writer, errorOutput io.Writer) int {
	parsed, err := readUCI(commandCheckDNSFlagUCI)
	if err != nil {
		io.WriteString(errorOutput, "error: "+sharelink.OneLine(err.Error())+"\n")
		return 2
	}
	// a file of dnsmasq that cannot be read is a dnsmasq that is not set up
	dhcp, _ := readUCI(commandCheckDNSFlagDHCP)
	// as written, without the defaults of the generator: the check reports the settings
	settings := parsed.Section("settings")
	var upstreams []model.DNSUpstream
	for _, row := range parsed.SectionsOfType("dns_server") {
		upstreams = append(upstreams, model.DNSUpstream{Type: row.Get("type"), Server: row.Get("server")})
	}
	if len(upstreams) == 0 {
		upstreams = []model.DNSUpstream{{Type: settings.Get("dns_type"), Server: settings.Get("dns_server")}}
	}
	report := diag.CheckDNS(context.Background(), diag.DNSSettings{
		Upstreams: upstreams,
		Mode:      settings.Get("dns_mode"),
		Bootstrap: settings.Get("bootstrap_dns_server"),
	}, dhcp)
	content, err := json.MarshalIndent(ctl.AnswerDNS(report), "", "  ")
	if err != nil {
		io.WriteString(errorOutput, "error: "+err.Error()+"\n")
		return 1
	}
	output.Write(append(content, '\n'))
	return 0
}

// By hand and for the lab: what the backend does to dnsmasq, one step at a time.
var commandDnsmasq = &cobra.Command{
	Use:       "dnsmasq take-over|restore",
	Short:     "Point the DNS of the LAN at the backend, or give dnsmasq back what it had",
	Args:      cobra.ExactArgs(1),
	ValidArgs: []string{"take-over", "restore"},
	Run: func(cmd *cobra.Command, args []string) {
		var changed bool
		var err error
		switch args[0] {
		case "take-over":
			changed, err = dnsmasq.TakeOver(dnsmasq.Router{})
		case "restore":
			changed, err = dnsmasq.Restore(dnsmasq.Router{})
		default:
			err = E.New("take-over or restore")
		}
		if err != nil {
			os.Stderr.WriteString("error: " + err.Error() + "\n")
			os.Exit(1)
		}
		if changed {
			os.Stdout.WriteString("changed, dnsmasq restarted\n")
		} else {
			os.Stdout.WriteString("nothing to change\n")
		}
	},
}

func init() {
	mainCommand.AddCommand(commandDnsmasq)
}

func readUCI(path string) (*uci.Package, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return uci.Parse(content)
}

func renderSettings(output io.Writer, errorOutput io.Writer) int {
	outcome, err := render.Run(render.Request{
		UCIPath:    commandRenderFlagUCI,
		Facts:      plan.Facts{LANAddress: commandRenderFlagLANAddress},
		OutputPath: commandRenderFlagOutput,
		RuleSetDir: commandRenderFlagRuleSetDir,
		Root:       commandRenderFlagRoot,
		SkipCheck:  commandRenderFlagNoCheck,
	})
	if err != nil {
		io.WriteString(errorOutput, "error: "+sharelink.OneLine(err.Error())+"\n")
		return 2
	}
	for _, warning := range outcome.Warnings {
		io.WriteString(errorOutput, "warning: "+sharelink.OneLine(warning)+"\n")
	}
	if outcome.Changed {
		io.WriteString(output, "written "+outcome.ConfigPath+"\n")
	} else {
		io.WriteString(output, "unchanged "+outcome.ConfigPath+"\n")
	}
	return 0
}
