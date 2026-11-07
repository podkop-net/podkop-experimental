//go:build linux

package main

import (
	"context"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/podkop-net/podkop-experimental/src/backend"
	"github.com/podkop-net/podkop-experimental/src/backend/api"
	"github.com/podkop-net/podkop-experimental/src/backend/clock"
	"github.com/podkop-net/podkop-experimental/src/backend/dataplane"
	"github.com/podkop-net/podkop-experimental/src/backend/dnsmasq"
	"github.com/podkop-net/podkop-experimental/src/backend/firewall"
	"github.com/podkop-net/podkop-experimental/src/backend/logbuf"
	"github.com/podkop-net/podkop-experimental/src/backend/model"
	"github.com/podkop-net/podkop-experimental/src/backend/netcfg"
	"github.com/podkop-net/podkop-experimental/src/backend/probe"
	"github.com/podkop-net/podkop-experimental/src/backend/subscription"
	"github.com/podkop-net/podkop-experimental/src/backend/supervisor"
	"github.com/podkop-net/podkop-experimental/src/backend/ubus"
	"github.com/podkop-net/podkop-experimental/src/backend/uci"
	"github.com/podkop-net/podkop-experimental/src/backend/yacd"

	"github.com/spf13/cobra"
)

var commandDaemonFlagUCI string

var commandDaemon = &cobra.Command{
	Use:   "daemon",
	Short: "Run the backend: sing-box, the firewall, the routing and the DNS of the LAN, from the settings",
	Long: "Run the backend until it is told to end.\n\n" +
		"It brings the router up from the settings, with sing-box inside this process. SIGHUP\n" +
		"applies the settings again: only what differs is changed, and settings that cannot\n" +
		"be used change nothing. SIGTERM takes everything back and ends the process.\n\n" +
		"What happens is printed a line an event, \"[level] message\".",
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		// The page may run /usr/bin/podkop with any arguments (rpcd's file.exec). A backend it
		// started would be no service of procd: rpcd kills it at its exec timeout, and nothing
		// gives the router back its DNS, its firewall and its routing.
		if parentName() == "rpcd" {
			os.Stderr.WriteString("error: the backend runs as the service (/etc/init.d/podkop start), not as a command of the page\n")
			os.Exit(1)
		}
		// one backend at a time, and a way for the release command to know this one is gone
		lock, err := takeLock(false)
		if err != nil {
			os.Stderr.WriteString("error: another backend runs: " + err.Error() + "\n")
			os.Exit(1)
		}
		defer lock.Close()
		processSettings()
		// the packet traces of checks whose process was killed before it removed them
		_ = firewall.DisarmTraces()
		ctx, cancel := context.WithCancel(context.Background())
		signals := make(chan os.Signal, 4)
		signal.Notify(signals, syscall.SIGHUP, syscall.SIGTERM, os.Interrupt)
		reload := make(chan struct{}, 1)
		go func() {
			for received := range signals {
				if received == syscall.SIGHUP {
					// applying takes a while: one more request waits, more than one are one
					select {
					case reload <- struct{}{}:
					default:
					}
					continue
				}
				cancel()
			}
		}()
		// the log of this run, for the user interface: the backend's own lines, which also
		// go to the system log, and those of sing-box
		logs := logbuf.New(256 << 10)
		// the checks with made-up names: who reaches sing-box through FakeIP, see probe
		watcher := probe.NewWatcher()
		say := func(level string, message string) {
			os.Stdout.WriteString("[" + level + "] " + message + "\n")
			logs.Write("backend", level, message)
		}
		go probe.ServeDeadEnd(ctx, say)
		// the clock, before sing-box downloads lists and speaks TLS (see clock)
		keeper := &clock.Keeper{
			Log:       say,
			DoH:       func() string { return dohServer(commandDaemonFlagUCI) },
			UplinkDNS: netcfg.UplinkDNSServers,
		}
		keeper.AtStart(ctx)
		go keeper.Loop(ctx)
		// dnsmasq running with the configuration written for it (see dnsmasq.Watch)
		dnsmasqWatch := dnsmasq.NewWatch(say)
		go dnsmasqWatch.Loop(ctx)
		backend := supervisor.New(supervisor.Options{
			SettingsPath: commandDaemonFlagUCI,
			System:       supervisor.Router{},
			Watcher:      watcher,
			StatePath:    statePath,
			EndsPath:     endsPath,
			// the dashboard of the package, served from a copy sing-box may write
			YACDBuiltinDir: yacd.BuiltinDir,
			YACDServedDir:  yacd.ServedDir,
			ConfigDir:      configDir,
			DownloadURL:    downloadURL,
			Clock:          keeper,
			Dnsmasq:        dnsmasqWatch,
			// the lists of the subscriptions stay over a reboot: a start without the
			// network has the servers
			SubscriptionDir: dataplane.DataDir + "/subscriptions",
			Device:          subscription.ReadDevice("/"),
			Version:         podkop.Version,
			Log:             say,
			EngineLog: func(level string, message string) {
				logs.Write("sing-box", level, message)
			},
		})
		go func() {
			err := api.Serve(ctx, api.SocketPath, backend, logs)
			if err != nil {
				os.Stdout.WriteString("[warn] the socket for commands is not there: " + err.Error() + "\n")
			}
		}()
		// the commands of the page answered here, with no program started for a call
		go ubus.Serve(ctx, ubus.Socket(), busObject(ctlEnvironment(), backend), func(message string) {
			say("warn", message)
		})
		if err := backend.Run(ctx, reload); err != nil {
			// sing-box did not close and holds its sockets: the router is given back, and
			// a new process is the only way on
			os.Stdout.WriteString("[error] the backend ends: " + err.Error() + "\n")
			os.Exit(1)
		}
	},
}

var commandRelease = &cobra.Command{
	Use:   "release",
	Short: "Give the router back what a backend that is gone left taken",
	Long: "Give the router back what a backend left taken: the DNS of the LAN, the firewall\n" +
		"table, the routing. A backend that ends as it should does this itself; this command is\n" +
		"for the one that was killed. It waits for a running backend to end first, and does\n" +
		"nothing when there is nothing to give back.",
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		lock, err := takeLock(true)
		if err != nil {
			os.Stderr.WriteString("error: the backend still runs: " + err.Error() + "\n")
			os.Exit(1)
		}
		defer lock.Close()
		say := func(level string, message string) {
			os.Stdout.WriteString("[" + level + "] " + message + "\n")
		}
		supervisor.New(supervisor.Options{
			System:    supervisor.Router{},
			ConfigDir: configDir,
			Dnsmasq:   dnsmasq.NewWatch(say),
			Log:       say,
		}).Release()
	},
}

const (
	// statePath tells what the backend is doing: the init script waits by it after a
	// start, and the next backend tells by it how this one ended.
	statePath = dataplane.RunDir + "/state"
	// endsPath counts the ends of the backend without its stop in a row.
	endsPath = dataplane.RunDir + "/ends"
	// configDir keeps the configuration that runs and the last one refused, for
	// show_sing_box_config.
	configDir = dataplane.RunDir
	// downloadURL is the download test of urltest groups whose section keeps the
	// default: 64 KiB through the member before a group switches to it. A server frozen
	// after ~16 KB passes the usual small test, not this one. podkop-engine set it for its
	// sing-box service; the backend writes it into the configuration itself.
	downloadURL = "https://speed.cloudflare.com/__down?bytes=65536"
	// workDir is the working directory of sing-box, where YACD is downloaded to.
	workDir = dataplane.DataDir
	// fileLimit is the number of open files the backend may have. The default of a
	// service, 4096, runs out at some 2000 proxied connections, and then DNS queries fail
	// for want of a socket.
	fileLimit = 65536
)

// processSettings sets what the process needs whatever started it: an init script
// that a package manager kept from another package would give none of it.
func processSettings() {
	var limit syscall.Rlimit
	if syscall.Getrlimit(syscall.RLIMIT_NOFILE, &limit) == nil && limit.Cur < fileLimit {
		wanted := syscall.Rlimit{Cur: fileLimit, Max: max(limit.Max, fileLimit)}
		if syscall.Setrlimit(syscall.RLIMIT_NOFILE, &wanted) != nil {
			// not allowed to raise the ceiling: as far as it goes
			wanted = syscall.Rlimit{Cur: limit.Max, Max: limit.Max}
			_ = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &wanted)
		}
	}
	if os.MkdirAll(workDir, 0o755) == nil {
		_ = os.Chdir(workDir)
	}
	// a rule set with nothing cached starts empty and is downloaded after the start: an
	// apply that adds a list does not leave the LAN without DNS while it downloads. The
	// environment tells sing-box, unless the service says otherwise.
	if _, set := os.LookupEnv(startEmptyVariable); !set {
		_ = os.Setenv(startEmptyVariable, "1")
	}
}

// startEmptyVariable is the switch of sing-box (route/rule) for rule sets that start
// empty instead of downloading during the start.
const startEmptyVariable = "SING_BOX_RULE_SET_START_EMPTY"

// dohServer is the DNS server of the settings when it is DoH (host[:port][/path]): the time
// of its HTTPS answers sets a clock no NTP server could (clock.Keeper.DoH).
func dohServer(path string) string {
	content, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	parsed, err := uci.Parse(content)
	if err != nil {
		return ""
	}
	config, err := model.Load(parsed)
	if err != nil || config.Settings.DNSType != "doh" {
		return ""
	}
	return config.Settings.DNSServer
}

// lockPath is the file a running backend holds locked.
const lockPath = "/var/run/podkop.lock"

// lock takes the lock of the backend. With patience it waits for a backend that is
// ending, as long as the service manager gives one to end and a little more.
func takeLock(patience bool) (*os.File, error) {
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(40 * time.Second)
	for {
		err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return file, nil
		}
		if !patience || time.Now().After(deadline) {
			file.Close()
			return nil, err
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func init() {
	commandDaemon.Flags().StringVar(&commandDaemonFlagUCI, "uci", "/etc/config/podkop", "The settings file")
	mainCommand.AddCommand(commandDaemon, commandRelease)
}

// parentName is the name of the process that started this one, as the kernel has it.
func parentName() string {
	content, err := os.ReadFile("/proc/" + strconv.Itoa(os.Getppid()) + "/comm")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(content))
}
