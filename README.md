# podkop-exp

[Русский](README.ru.md)

A place to test new functionality of [podkop](https://github.com/itdoginfo/podkop). What is tried
here may later go to podkop, change, or go away.

podkop-exp is installed instead of podkop and keeps its settings file (`/etc/config/podkop`) and
its LuCI page. The backend is one program written in Go with sing-box inside, so no sing-box
package is needed.

## What it adds to podkop

- **One backend with the engine inside.** The page asks the running backend, so it barely loads
  the router. If the backend crashes again and again, the router gets its own DNS back.
- **The engine is [podkop-engine](https://github.com/podkop-net/podkop-engine)**, a build of
  sing-box. It works with current Xray servers (REALITY with X25519MLKEM768) and supports the XHTTP
  transport and VLESS Encryption.
- **Servers apart from rules.** Subscriptions, links, outbound JSON and interfaces are on the
  "Servers" tab. A rule takes its servers from them by words in their names, and can connect
  through another source.
- **Subscriptions downloaded by the router.** The device identifier (HWID) is taken from the
  hardware. The provider's traffic and end date are shown. A change of the list does not
  restart sing-box, so open connections stay.
- **Automatic server choice per rule:** the fastest server, the fastest that avoids loss, or a
  balance between the best. Fallbacks ("Directly", "Block", other servers) take over when no
  server answers. A server can be pinned on the dashboard.
- **Block detector and treatments.** A server that does not work is marked with the cause (no
  answer, freeze, limit, no path …). "Check server" probes it and can offer a treatment: a mask
  of a whitelisted site, a split ClientHello, or a connection through another server.
- **uTLS fallback, on by default.** The link's TLS fingerprint is tried first without the
  X25519MLKEM768 key share that DPI freezes, then firefox, then as it is. The first that passes is
  remembered for the server.
- **Downloads that get through.** Lists and subscriptions that do not come directly come through
  the servers of your rules. The way that worked last time is tried first.
- **DNS:** several servers (DoH, DoT, UDP, the provider's DNS), asked in order or fastest first.
  The provider's DNS is the fallback, on every uplink. After a reboot, dnsmasq still sends DNS queries to podkop.
  Per-domain forwardings (Tailscale) are kept.
- **BitTorrent:** a setting sends it past podkop, blocks it or sends it through the servers of a
  rule, for what podkop takes or for the whole LAN, and for a client on the router itself. Its
  statistics are on the dashboard. What it cannot do is in the [guide](docs/GUIDE.md#bittorrent).
- **Dashboard and diagnostics:** the route of each rule, the servers with their delay and loss,
  and the BitTorrent traffic. The global check also covers the router's clock, the running state
  of dnsmasq, the server choice and an MTU hint for VPN interfaces.
- **Several uplinks:** mwan3 (balance and failover), PPPoE, routes to single hosts and Tailscale
  work.
- **YACD in the package**, open only from the devices you choose.
- **Your podkop settings are converted** at install, and the old file is kept for going back.

## Install

OpenWrt 24.10 or newer, at least 80 MB of RAM. In the router's shell:

```sh
sh <(wget -O - https://raw.githubusercontent.com/podkop-net/podkop-experimental/main/install.sh)
```

The installer checks the router. It offers to remove podkop and the packages that conflict with
podkop-exp; if the flash is short, it also offers to remove sing-box packages that podkop-exp
does not need. Then it installs podkop-exp and its page, with the Russian translation if you want
it. podkop's settings are converted; the file as it was stays as `/etc/config/podkop.pre-0.8.8`.

To upgrade, run the same command. Clear the browser's cache of the LuCI page after an upgrade.

## Back to podkop

Remove the packages (leave out `luci-i18n-podkop-exp-ru` if you did not install the translation):

```sh
opkg remove luci-i18n-podkop-exp-ru luci-app-podkop-exp podkop-exp   # OpenWrt 24.10
apk del luci-i18n-podkop-exp-ru luci-app-podkop-exp podkop-exp       # OpenWrt 25.12
```

Put the old settings back with `mv /etc/config/podkop.pre-0.8.8 /etc/config/podkop` (if there is no such file, remove
`/etc/config/podkop`). Then install podkop as its README says.

## Documentation

| | |
|---|---|
| [User guide](docs/GUIDE.md) | first start, the tabs of the page, what to do when something does not work |
| [Changelog](CHANGELOG.md) | what changed in each release |
| [Releases](https://github.com/podkop-net/podkop-experimental/releases) | packages and the full release notes |
| [Link examples](String-example.md) | examples of proxy links (SOCKS, Shadowsocks, VLESS, Trojan, Hysteria2) |
| [podkop-engine](https://github.com/podkop-net/podkop-engine) | the sing-box build inside podkop-exp |
| [Backend](src/backend/README.md) | for developers: how the backend is built and tested |

Problems and questions: [issues](https://github.com/podkop-net/podkop-experimental/issues). Attach
the output of the global check, as the [guide](docs/GUIDE.md#when-something-does-not-work)
says.
