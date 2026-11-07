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
| `cmd/podkop` | The program: `daemon`, `release`, `ctl <command>`; the commands of the page without `ctl` |
| `supervisor` | The running backend: start, apply of changed settings, stop, the state left for a restart |
| `model`, `uci` | The settings read from the UCI file, with the defaults and the checks |
| `plan` | The settings made into a sing-box configuration and rule-set files |
| `engine` | The only package that imports sing-box: build, check and run a configuration |
| `dataplane`, `firewall`, `netcfg`, `dnsmasq` | The nftables table (over netlink), the routing rule and route, the DNS of the LAN |
| `lists` | The lists: downloads, updates, the nftables sets of subnets |
| `api`, `ctl` | The socket of the running backend and the commands of the page on top of it |
| `diag`, `probe`, `clock` | The checks of the page, the probe of the data path, the help of the router's NTP service (sysntpd) |
| `render`, `logbuf` | What a start writes before sing-box runs; the last lines of the log in memory |
| `compat.go` | What is kept only for podkop 0.7, each item with when it can go |

`imports_test.go` holds the rule that only `engine` imports sing-box: a new version of
sing-box is one package to port.

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

The tag `lab` adds commands for test stands (`render`, `check-dns`, `dnsmasq`, `nft`); the
package is built without it.

The package (`podkop/Makefile`) builds the same in the OpenWrt SDK. The Go of the 24.10 SDK
is too old: `sdk/golang-feed.sh` puts `lang/golang` of a later packages feed into the SDK
first (the Dockerfiles run it).

## On the router

- `/etc/init.d/podkop` runs `podkop daemon` under procd, which starts a backend that ended
  without its stop again for good. The backend started tells by `/var/run/podkop/state` that
  the one before ended so, and after a few such ends in a row gives the router its own DNS
  back and tries again later (`/var/run/podkop/ends` counts them).
- The running backend listens on `/var/run/podkop/ctl.sock`; the commands of the page ask
  it there.
- The log: `logread -e podkop`, or `podkop check_logs`.
- `podkop release` gives the router back the DNS of the LAN, the firewall table and the
  routing that a backend which is gone left taken (the init script runs it at the stop).
