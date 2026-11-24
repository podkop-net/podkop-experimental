# The backend of podkop (Go)

One program, `/usr/bin/podkop`: the backend of podkop with sing-box inside it. sing-box is
not a separate package and process any more: it is a Go module the backend builds with
(podkop-engine, the sing-box of podkop). To the system the program is not sing-box: there is
no `/usr/bin/sing-box` of it, it uses neither the settings (`/etc/config/sing-box`) nor the
directories (`/etc/sing-box`, `/usr/share/sing-box`) of a sing-box package, and one may be
installed beside it. Its own files are in `/var/run/podkop` (RAM: the configuration that
runs, the rule-set files) and `/usr/share/podkop` (the cache file when it is on flash).

The settings stay `/etc/config/podkop` in the format of podkop 0.7, and the page (LuCI)
calls the same commands (`podkop get_status`, `podkop check_logs`, ...).

## Packages

| Package | What it is |
|---|---|
| `.` (`podkop`) | The version of the backend and of the engine release, the build (full or slim), the list of what is kept only for podkop 0.7 (`compat.go`), and the tests of the layout (below) |
| `cmd/podkop` | The program: `daemon`, `release`, `migrate`, `boot-dns`, `ctl <command>` (the commands of the page, also without `ctl`), and the object `podkop` the running backend publishes on ubus; with the tag `lab` also `render`, `check-dns`, `dnsmasq`, `nft`, `parse-list` |
| `supervisor` | The running backend: start, apply of changed settings, stop, the state left for a restart; the downloads of the subscriptions and of the mask lists, the cures of the block detector |
| `model` | The settings of the UCI file (format 2: settings, sources, rules and their rows) with the defaults and the reading of the shell backend, the names the tags are made of, the devices of a rule |
| `uci` | UCI files read as libuci reads them, and written back, without the `uci` program |
| `migrate` | The settings of podkop 0.7 and of podkop-exp before 0.8.8 converted to the format 2 |
| `plan` | The settings made into a sing-box configuration and its rule-set files, with what the firewall and the routing need around it |
| `render` | The configuration and the rule-set files of a start written, with sing-box's check of them (`Check`, the supervisor's `Engine.Check`); the atomic write of a file |
| `engine` | The way to sing-box: an instance built, checked, run and swapped; links decoded, rule sets read, servers probed through it |
| `engine/bittorrent` | podkop's BitTorrent module, a service of sing-box: it learns the peers of trackers and of the DHT, checks connections, and writes the nftables sets the firewall owns |
| `dataplane` | The values the configuration and the router agree on: the addresses and ports of the inbounds, the marks, the FakeIP range, the routing and firewall tables; the mark of the backend's own sockets (`MarkedControl`) |
| `firewall` | The nftables table of the backend over netlink, without the `nft` program: its rules and sets, the detector of BitTorrent, the conntrack entries it marks, the trace tables of the checks |
| `netcfg` | The routing: the rules and the route that hand marked packets to the transparent proxy, those of the uplinks, the address of the LAN, the devices interface names stand for |
| `dnsmasq` | The DNS of the LAN pointed at the backend and back, in dnsmasq's own settings, and the watch that dnsmasq runs with them |
| `lists` | The destinations the rule sets name, for the firewall's sets of subnets (sing-box downloads the lists itself) |
| `subscription` | The list of a subscription: downloaded (the ways, the retries, the headers, the device), read (links, base64, Xray and sing-box JSON), checked against the engine of the build, kept |
| `detect` | The block detector: what stops a proxy server, from what the engine observed or from an active probe; no network or engine of its own |
| `probe` | The check names: a made-up name answered from FakeIP and the connection to it tell that a device reaches sing-box |
| `btstats` | What the BitTorrent traffic of the LAN came to, by its kind and its way, from the conntrack entries and the counters of the drops |
| `clock` | Help for the router's NTP service (sysntpd) while the clock is wrong: NTP, the time of HTTPS answers |
| `api` | The socket of the running backend: the types of its answers, the server and the client; the same questions asked inside the backend, with no socket (`Direct`) |
| `ctl` | The commands of the page and of the CLI, in one table (`Methods`) the help, `Run`, the commands the running backend answers itself on ubus and its object there are made from: the checks, the global check, `device`, the calls of the Clash API |
| `ubus` | The protocol of ubusd, so that the running backend publishes an object of its own |
| `diag` | The checks behind the global check: DNS, the firewall, sing-box, forwards, the trace of packets, the masking of secrets |
| `sockets` | Who listens where, from `/proc` |
| `yacd` | The dashboard YACD where sing-box serves it; its upgrade from GitHub kept apart from the package's files |
| `logbuf` | The last lines of the log in memory, the backend's and sing-box's |
| `serverid` | The stable identity of a server whatever its tag or detour: the key of a cure, shared by the subscription parser, the planner and the cure store |

The tests of the layout, in the root package: `imports_test.go` holds the rule that only
`engine`, `engine/bittorrent` and `cmd/podkop` import sing-box, so that a new version of sing-box
is one package to port; `doors_test.go` lists the other ways to it (the Clash API, the switches
of the engine's environment); `edges_test.go` holds the import edges between the packages to
`testdata/import-edges.txt`.

## sing-box: podkop-engine as a module

`go.mod` requires `github.com/sagernet/sing-box` at the release podkop-engine is based on,
and replaces it with the podkop-engine line in the fork
[podkop-net/sing-box](https://github.com/podkop-net/sing-box) (branch `podkop-engine-1.14`). The
replace of `sing-vmess` repeats the one of podkop-engine's own `go.mod`:
Go applies a `replace` only in the main module.

To move to another commit of podkop-engine:

```sh
go mod edit -replace=github.com/sagernet/sing-box=github.com/podkop-net/sing-box@<commit>
go mod tidy
```

The package takes the version of sing-box the page shows (`podkop show_sing_box_version`)
from these lines: `<release>-pdk-<commit>`.

## Build and test

The build tags and `-checklinkname=0` are the ones podkop-engine and sing-box build with
(some dependencies link to internals of the standard library).

```sh
TAGS=with_quic,with_utls,with_clash_api,podkop_slim,badlinkname,tfogo_checklinkname0
go vet -tags $TAGS ./...
go test -tags $TAGS -ldflags=-checklinkname=0 -race ./...
CGO_ENABLED=0 go build -trimpath -tags $TAGS \
  -ldflags "-s -w -checklinkname=0 -X github.com/podkop-net/podkop-experimental/src/backend.Version=0.8.0" \
  -o podkop ./cmd/podkop
```

The tag `lab` adds commands for test stands (`render`, `check-dns`, `dnsmasq`, `nft`,
`parse-list`); the package is built without it.

The package (`podkop/Makefile`) builds the same in the OpenWrt SDK. The Go of the 24.10 SDK
is too old: `sdk/golang-feed.sh` puts `lang/golang` of a later packages feed into the SDK
first (the Dockerfiles run it).

## On the router

- `/etc/init.d/podkop` runs `podkop daemon` under procd, which starts a backend that ended
  without its stop again for good. The backend started tells by `/var/run/podkop/state` that
  the one before ended so, and after a few such ends in a row gives the router its own DNS
  back and tries again later (`/var/run/podkop/ends` counts them).
- The running backend listens on `/var/run/podkop/ctl.sock`; the commands of the program ask
  it there. Those it answers itself on ubus (`ubus call podkop run`, as the page does) ask it
  with no socket.
- The log: `logread -e podkop`, or `podkop check_logs`.
- `podkop release` gives the router back the DNS of the LAN, the firewall table and the
  routing that a backend which is gone left taken (the init script runs it at the stop).
