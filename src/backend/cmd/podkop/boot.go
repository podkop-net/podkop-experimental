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

var commandBootDNS = &cobra.Command{
	Use:   "boot-dns",
	Short: "At boot, before dnsmasq starts: set it to ask the backend",
	Long: "For /etc/init.d/podkop-early, which runs it at boot before dnsmasq starts when podkop\n" +
		"starts at boot: dnsmasq is set to ask the backend as the backend sets it, without a\n" +
		"reload, unless dont_touch_dhcp is on or a backend runs. The backend then finds it set\n" +
		"and does not reload it.",
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(bootDNS(os.Stdout, "/etc/config/podkop", dnsmasq.Router{}, func() (io.Closer, error) {
			return takeLock(false)
		}))
	},
}

func init() {
	mainCommand.AddCommand(commandBootDNS)
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
		io.WriteString(output, "[info] dnsmasq starts asking the backend: the backend does not reload it at its start\n")
	}
	return 0
}
