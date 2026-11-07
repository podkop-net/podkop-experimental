//go:build linux

package main

import (
	"io"
	"os"

	"github.com/podkop-net/podkop-experimental/src/backend/dnsmasq"
	"github.com/podkop-net/podkop-experimental/src/backend/model"
	"github.com/podkop-net/podkop-experimental/src/backend/uci"
	"github.com/sagernet/sing-box/common/sharelink"

	"github.com/spf13/cobra"
)

var commandBootDNSFlagGiveBack bool

var commandBootDNS = &cobra.Command{
	Use:   "boot-dns",
	Short: "At boot, before dnsmasq starts: set it to ask the backend",
	Long: "For /etc/init.d/podkop-early, which runs it at boot before dnsmasq starts when podkop\n" +
		"starts at boot: dnsmasq is set to ask the backend as the backend sets it, so that it\n" +
		"starts that way, unless dont_touch_dhcp is on or a backend runs. The backend then finds\n" +
		"it set and does not start it again.\n\n" +
		"With --give-back, when podkop does not start at boot: a dnsmasq that a backend which\n" +
		"ended without its stop left asking it is given back before it starts.",
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		lock := func() (io.Closer, error) { return takeLock(false) }
		if commandBootDNSFlagGiveBack {
			os.Exit(bootGiveBack(os.Stdout, dnsmasq.Router{}, lock))
		}
		os.Exit(bootDNS(os.Stdout, "/etc/config/podkop", dnsmasq.Router{}, lock))
	},
}

func init() {
	commandBootDNS.Flags().BoolVar(&commandBootDNSFlagGiveBack, "give-back", false, "Give dnsmasq back instead: podkop does not start at boot")
	mainCommand.AddCommand(commandBootDNS)
}

// bootGiveBack gives dnsmasq back before it starts at boot (dnsmasq.GiveBackBeforeStart),
// unless a backend runs (one started by hand before this ran). The firewall table and the
// routing of a backend do not outlive a boot.
func bootGiveBack(output io.Writer, system dnsmasq.System, lock func() (io.Closer, error)) int {
	held, err := lock()
	if err != nil {
		io.WriteString(output, "[info] a backend runs: dnsmasq is left to it\n")
		return 0
	}
	defer held.Close()
	changed, err := dnsmasq.GiveBackBeforeStart(system)
	if err != nil {
		io.WriteString(output, "[error] give dnsmasq back before it starts: "+sharelink.OneLine(err.Error())+"\n")
		return 1
	}
	if changed {
		io.WriteString(output, "[info] dnsmasq asked a backend that ended without its stop: it starts with the router's servers, podkop does not start at boot\n")
	}
	return 0
}

// bootDNS sets dnsmasq to ask the backend before it starts at boot (see dnsmasq.Prepare). The
// backend that starts later takes it as it would at its start, and gives it back when its
// start fails; its stop gives it back too, so that an image flashed meanwhile or a boot with
// the autostart off has dnsmasq as it was. lock takes the lock of a running backend.
func bootDNS(output io.Writer, settingsPath string, system dnsmasq.System, lock func() (io.Closer, error)) int {
	fail := func(message string) int {
		io.WriteString(output, "[error] dnsmasq is set when the backend starts: "+sharelink.OneLine(message)+"\n")
		return 1
	}
	// one started by hand before this ran has dnsmasq already: the backend's business
	held, err := lock()
	if err != nil {
		io.WriteString(output, "[info] a backend runs: dnsmasq is left to it\n")
		return 0
	}
	defer held.Close()
	content, err := os.ReadFile(settingsPath)
	if err != nil {
		return fail(err.Error())
	}
	parsed, err := uci.Parse(content)
	if err != nil {
		return fail(err.Error())
	}
	config, err := model.Load(parsed)
	if err != nil {
		return fail(err.Error())
	}
	if config.Settings.DontTouchDHCP {
		return 0
	}
	changed, err := dnsmasq.Prepare(system)
	if err != nil {
		return fail(err.Error())
	}
	if changed {
		io.WriteString(output, "[info] dnsmasq starts asking the backend: the backend does not start it again at its start\n")
	}
	return 0
}
