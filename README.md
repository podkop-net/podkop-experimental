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
  restart sing-box, so open connections stay. A provider that gives the list only to some apps
  can be asked as Happ, INCY, sing-box or another app (User-Agent), with extra headers; the HWID
  stays the router's own. Besides a list of links, the servers of Xray JSON and sing-box JSON are
  read (only the servers: the provider's rules and DNS are not used).
- **Automatic server choice per rule:** the fastest server, the fastest that avoids loss, or a
  balance between the best. Fallbacks ("Directly", "Block", other servers) take over when no
  server answers. A server can be pinned on the dashboard.
- **Rules for some devices:** a rule can take the traffic of chosen devices only (IPv4 or IPv6
  addresses and subnets), for example YouTube through the servers on the TV alone and blocked on
  the rest ([guide](docs/GUIDE.md#a-rule-for-some-devices)).
- **Block detector and treatments.** A server that does not work is marked with the cause (no
  answer, freeze, limit, no path …). "Check server" probes it and can offer a treatment: a mask
  of a whitelisted site, a split ClientHello, or a connection through another server.
- **uTLS fallback, on by default.** The link's TLS fingerprint is tried first without the
  X25519MLKEM768 key share that DPI freezes, then firefox, then as it is. The first that passes is
  remembered for the server.
- **Downloads that get through.** Lists and subscriptions that do not come directly come through
  the servers of your rules. The way that worked last time is tried first.
- **DNS:** several servers (DoH, DoT, UDP, the provider's DNS; IPv4 or IPv6), asked in order or
  fastest first; answers with IPv4 first, IPv4 only, or both.
  The provider's DNS is the fallback, on every uplink. After a reboot, dnsmasq still sends DNS queries to podkop.
  Per-domain forwardings (Tailscale) are kept.
- **BitTorrent:** a setting sends it past podkop, blocks it or sends it through the servers of a
  rule, for what podkop takes or for the whole LAN, and for a client on the router itself. Its
  statistics are on the dashboard. What it cannot do is in the [guide](docs/GUIDE.md#bittorrent).
- **Dashboard and diagnostics:** the route of each rule, the servers with their delay and loss,
  and the BitTorrent traffic. The global check also covers the router's clock, the running state
  of dnsmasq, the server choice and an MTU hint for VPN interfaces.
- **IPv6:** past podkop, or through it for the IPv6 subnets of the lists, as IPv4
  ([guide](docs/GUIDE.md#ipv6)).
- **Several uplinks:** mwan3 (balance and failover), PPPoE, routes to single hosts and Tailscale
  work.
- **YACD in the package**, open only from the devices you choose.
- **Your podkop settings are converted** at install, and the old file is kept for going back.

## Install

OpenWrt 24.10 or newer, at least 80 MB of RAM. In the router's shell (SSH):

```sh
sh <(wget -O - https://raw.githubusercontent.com/podkop-net/podkop-experimental/main/install.sh)
```

If the shell does not take that line, download the installer first:

```sh
wget -O /tmp/install.sh https://raw.githubusercontent.com/podkop-net/podkop-experimental/main/install.sh && sh /tmp/install.sh
```

The installer checks the router and shows what it will do: the release, the version installed
now, and the installed packages podkop-exp cannot work beside (podkop and its page, podkop-engine;
https-dns-proxy, nextdns or luci-app-xray, which take over the DNS forwarding of dnsmasq). It asks
once whether to remove them, and whether to install the Russian translation, before it changes
anything: if you answer no, nothing on the router is changed. Your podkop settings stay:
podkop-exp converts them and keeps them in the old format as `/etc/config/podkop.pre-0.8.8` (if
that file is left from an earlier install, the installer first copies the current file to a dated
name and tells it). If the flash is short, it then offers to remove the sing-box packages nothing
uses (podkop-exp has sing-box inside). It shows the output of every command as it goes; when
something fails, it says what was done already.

Options, at the end of the command:

| | |
|---|---|
| `-y` | yes to the questions, for scripts: remove the packages podkop-exp cannot work beside and the unused sing-box packages, install an older release named by `--release`. The translation stays as it is: kept if it was installed |
| `--ru`, `--no-ru` | install the Russian translation of the page without the question, or leave it out |
| `--release 0.8.19` | that release instead of the latest one, an older one too (0.8.8 or newer). An older release does not undo the conversion of the settings, and it ignores the options added after it |
| `--from DIR` | the package files in `DIR` instead of a download ([below](#install-without-githubs-api)) |

Without a terminal (in a script), the answers are read from the input: `echo y | sh /tmp/install.sh`.

To upgrade, run the same command, then clear the browser's cache of the LuCI page (or open it in a
private window). When the release is installed already, the installer says so and changes nothing.

If podkop runs and the download fails, stop it (`service podkop stop`) and run the command again.
The installer says so when GitHub's address comes from podkop's FakeIP range.

### Install without GitHub's API

GitHub's API allows 60 requests an hour from one address, and the subscribers of a mobile operator
often share one. When the installer says "GitHub refused the request":

1. On a computer, download from the [release page](https://github.com/podkop-net/podkop-experimental/releases):
   - `podkop-exp-<version>-<architecture>.ipk` (`.apk` on OpenWrt 25.12). The architecture of the
     router, with dashes: `. /etc/openwrt_release; echo $DISTRIB_ARCH | tr _ -`. For example
     `podkop-exp-v0.8.20-r1-aarch64-cortex-a53.ipk`;
   - `luci-app-podkop-exp-<version>-all.ipk` (`luci-app-podkop-exp-<version>.apk`);
   - for Russian, `luci-i18n-podkop-exp-ru-<version>.ipk` (`.apk`).
2. Copy them to the router. `-O`: the SSH server of OpenWrt (dropbear) has no SFTP, which `scp`
   uses by default.

   ```sh
   ssh root@192.168.1.1 mkdir -p /tmp/pkgs
   scp -O podkop-exp-* luci-app-podkop-exp-* luci-i18n-podkop-exp-ru-* root@192.168.1.1:/tmp/pkgs/
   ```

3. Add `--from /tmp/pkgs` at the end of the install command. The installer does not check these
   files against GitHub's digests: take them from the release page only. If the router cannot
   reach GitHub at all, copy `install.sh` there as well and run
   `sh /tmp/pkgs/install.sh --from /tmp/pkgs`.

## Back to podkop

Remove the packages (leave out `luci-i18n-podkop-exp-ru` if you did not install the translation):

```sh
opkg remove luci-i18n-podkop-exp-ru luci-app-podkop-exp podkop-exp   # OpenWrt 24.10
apk del luci-i18n-podkop-exp-ru luci-app-podkop-exp podkop-exp       # OpenWrt 25.12
```

Put the old settings back with `mv /etc/config/podkop.pre-0.8.8 /etc/config/podkop` (if there is no such file, remove
`/etc/config/podkop`; if the installer named a dated copy, `/etc/config/podkop.pre-0.8.8-<date>`,
that one holds the settings of your last podkop). Then install podkop as its README says.

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
