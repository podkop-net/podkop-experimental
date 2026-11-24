# Changelog

[Русский](CHANGELOG.ru.md)

What changed in each release of podkop-exp, newest first. The engine is the sing-box build
[podkop-engine](https://github.com/podkop-net/podkop-engine) the release has inside. The full
notes, with the measurements and the limits, are on the
[releases page](https://github.com/podkop-net/podkop-experimental/releases).

## 0.8.23 — not released yet

Engine r29. In the server choices that count loss (avoiding loss, balance) the loss checks run only
while the servers are in use; an idle fallback downloads nothing for them (r28: 2 to 3 MB an hour for
each rule at the defaults). A group that comes into use starts with checks of 1 MB, so loss decides
in seconds after a switch instead of hours. A balance not in use keeps one choice and stops
rechecking its servers each round. An HTTP proxy connection kept alive across a restart no longer
answers one "502 Bad Gateway".

- **The choice among the fallbacks (new):** Rules → a rule → Fallback → Fallback choice. **In order**
  (the default, as before) uses a row only while nothing before it answers. **Fastest**, **Fastest,
  avoiding loss** and **Balance between the best** choose among the servers of all the rows
  together; Directly or Block then comes last, wherever its row is. While the servers of the rule
  answer, the loss of the fallbacks is not checked. The dashboard shows the fallbacks as one tier
  named by the choice; the global check tells what loss and balance have counted.
- **Protocols of the rows (new):** a row of Servers or Fallback takes only the servers of the chosen
  protocols (VLESS, VMess, Trojan, Shadowsocks, Hysteria2, Hysteria, TUIC, AnyTLS, Naive, SOCKS,
  HTTP), with the words of its names as before. Links and JSON count as their protocol; an
  interface has none and is always taken. The list in the window counts what is chosen. A name that
  is no protocol warns in the log and takes nothing.
- **The Servers list shows the traffic of a subscription without a limit** ("1.2 GB, no limit").
  Subscriptions with a limit were already shown.
- **A bar when the page and the backend are of different versions (new):** after an update the
  browser may keep the old page. The bar says which is older and reloads the page past the cache
  (Ctrl+F5 does not do it in Chrome). It is not shown when the versions are the same or not known.
- **Settings are written safely:** the backend replaces `/etc/config/podkop` as a whole, under the
  lock of `uci`. With no room left on the flash, the 0.7 → podkop-exp upgrade could leave an empty
  settings file (`uci commit` does that on a full flash); now the file stays as it was, and the
  conversion runs when there is room. The copy of the old settings is made whole or not at all; when
  it cannot be made, nothing else is changed. `option x` without a value no longer makes the backend
  refuse the file.
- `podkop migrate` does what the upgrade script did with the settings, in the same order and under
  the same conditions. Checked on 940 settings files against 0.8.22 on OpenWrt 23.05, 24.10 and 25.12:
  910 the same on each, the same 30 differ in corners (files LuCI cannot read, an owner or a
  symlink kept as it was, changes not yet committed).
- Fixed: `podkop subscription_update` before the settings could be read ended the backend; "update
  all" without a subscription could stop it for good when the caller was gone; the user of a torrent
  client on the router that went away was not noticed until a network event.
- For developers: the commands of the backend are one table the help, the dispatch, the methods on
  ubus and the page's `run` are made from; `run` asks the backend without its socket. The
  supervisor has its subscriptions, its BitTorrent and its block detector as parts of their own. The
  recordings of 0.8.22 hold byte for byte but for the intended changes.

## 0.8.22 — 2026-11-24

Engine r28, as 0.8.21.

- **Saved, applied, and what came of it (new):** a bar above the tabs. When changes are saved but
  not applied (the Save of a window or of the page keeps them only), it reads "Changes saved but not
  applied: N" with Save & Apply, Show and Revert. After Save & Apply it reads what the router did:
  "Applied 12:03: sing-box runs the new configuration", or "Not applied" with the reason, for
  example two mixed proxies on the same port. `podkop get_status` gives the same: whether the
  backend runs, since when, and what the last start or change of the settings came to.
- **The way back to podkop 0.7 works again:** the copy of the settings kept for it
  (`/etc/config/podkop.pre-0.8.8`) was taken after the upgrade had changed them, and podkop 0.7 put
  back from it routed nothing (no `config_path`). The copy is now the file as it was. Checked on
  OpenWrt 24.10 and 25.12: 0.7.24 → podkop-exp → 0.7.24 routes again. The copies kept by earlier
  releases stay wrong: after putting one back, run `uci set
  podkop.settings.config_path=/etc/sing-box/config.json; uci set
  podkop.settings.cache_path=/tmp/sing-box/cache.db; uci commit podkop` before installing podkop.
- **An interface source offers the tunnel of any program:** the tun of a VK TURN client such as
  CSQTT, or of a VPN client, was left out of the list unless its name began with tun, wg, ovpn…; any
  tunnel the router has now is offered, whatever its name. The list is read again each time the
  window opens, and a tunnel that is not up has to be typed by name, as the field says now. The same
  goes for the output interface in Settings.
- The community list Block is called Block in Russian too (it was "Блокировать", the action).
- **Subscriptions:** the page waiting for the download of a subscription that was removed or given
  another address meanwhile is answered at once (it waited up to 170 s). **Update now** runs inside
  the backend instead of starting a program for each click. Subscriptions due at the same time start
  in the order of their names.
- **`podkop device`** reads the rules the planner itself makes instead of a copy of their order. It
  tells a router without IPv6 (the IPv6 of a device then goes past podkop), says the reason when the
  settings cannot be used, and says that from an IPv6 address a rule of lists takes the connections
  to the IPv6 subnets of its lists only (the names of the lists get FakeIP IPv4 addresses).
- The log says that a subscription asked differently is downloaded again in 10 to 25 s (it said
  10 s), or as soon as the download under way ends; the line of a configuration names the LAN it
  takes when no source interface is set (br-lan). The installer counts every feed the router reads
  (it said "0 of them" for feeds outside distfeeds). `show_sing_box_version` is in the help.
- For developers: the tests run on every push and pull request (with nftables and iproute2 for the
  firewall's, the race detector on every package that starts goroutines, ShellCheck of every
  script). New tests record byte for byte what the planner builds (649 sets of settings, 597 of them
  0.7's after conversion), the nftables table and the routes in the kernel, the supervisor's course
  in 17 scenarios and the answers the page reads, and hold the ways into sing-box, the imports
  between the packages and the lists of commands. Under them the inner structure was reworked with no
  change to what they record: one tail for the applies, one exit for a downloaded list, the hooks of
  the BitTorrent module and the version of sing-box passed in instead of set globally, one intent of
  the router for the planner and the firewall, the types of the socket's answers below it, the
  helpers in one place each.

## 0.8.21 — 2026-11-22

Engine r28. A server whose link pins its certificate (`pcs`, `pinSHA256`) or names others to
verify it by (`vcn`) is now checked as Xray checks it; r27 checked it against the system roots
only, and a server with a certificate of its own failed. The hello cut a link sets (`fm`) is
applied, and Hysteria 2 links with port hopping (`udphop`) or gecko are read.

- **A rule for chosen devices (new): "Only for devices"** on the Main tab of a rule, IPv4 or IPv6
  addresses and subnets. The rule then takes the traffic of these devices only, and the rest of its
  conditions stay as they are: any of its lists. The other devices go on to the rules below, and
  directly when none takes them. For example, YouTube through the servers on the TV only, with a
  rule with Block below it for the other devices. The DNS answers stay the same for every device;
  the rule's mixed proxy is not limited by the field, and the router's own traffic is normally not
  taken. The page offers the devices the router knows; `podkop device <address>` lists the rules
  that take a device. Fully Routed IPs that sing-box cannot read are left out with a warning
  instead of refusing the whole configuration.
- **A login for the mixed proxy of a rule (new):** a user name and a password on the Extra tab, for
  SOCKS5 and HTTP; **Generate** fills in a random password. Without them the proxy stays open to
  every device that reaches its port, as before. The global check, `show_config`,
  `show_sing_box_config` and podkop's log hide the login; the global check tells for each proxy
  whether it listens and whether it asks for a login.
- **Ask as and extra headers of a subscription (new):** some providers give the servers only to
  the apps they name and send podkop a web page or notes. **Ask as** chooses the app the
  subscription is asked as: podkop (as before), Happ, INCY, sing-box (SFA) or another User-Agent
  typed by hand. **Load** shows what the provider sends to it.
- **Servers from Xray JSON and sing-box JSON (new):** podkop now reads the servers of a
  subscription that comes as Xray configurations (what Remnawave and other panels may send to Happ
  and INCY) or as a sing-box configuration (what they send to SFA), whatever it was asked as. Only
  the servers are taken: the provider's rules, DNS, balancers and groups are not used. A server the
  provider connects through another one is connected directly, with a note. Settings that sing-box
  cannot use are named in the server's notes. The window and the global check say which form was
  read.
  - The links of these servers are made by podkop and may read differently in other apps.
  - Clash YAML is still not read, nor are links encrypted for Happ (`happ://crypt…`); the window
    says so.
  - The router still sends its own device identifier (HWID) and device headers, which cannot be
    set here, nor can the client's address or the headers of the connection. The values of the
    extra headers are hidden in the global check and the log; on a redirect to another host they
    are not sent. A pasted `incy://import/…` link gives its address.
- **Test latency** no longer asks only www.gstatic.com: one server is tested with the first server
  check URL of the settings, and with the next one when it does not answer; a rule of several
  servers runs a round of its own server check. The direct line of the global check and of
  Diagnostics asks all the check URLs at once and names the ones that do not answer.
- **Diagnostics, the version:** "Outdated" no longer shows right after an upgrade. The release
  GitHub names is kept for the version of the page that asked, and the versions are compared in
  order: **Latest**, **Update available: vX** or **Test build**.
- **Install script:** every question comes before the first change, so "Nothing was changed" is
  true when you answer no; the question names the packages it removes and why, and says that your
  podkop settings stay. New options: `-y` (yes to the questions), `--release X.Y.Z` (that release,
  an older one too, 0.8.8 or newer), `--from DIR` (package files downloaded on a computer, when
  GitHub's API refuses: it allows 60 requests an hour from one address). GitHub's refusals are told
  apart; a download fails with a hint when api.github.com resolves to podkop's FakeIP.
- **Fixed:** a final answer of the provider on the direct way (such as a 404) no longer counts as a
  failure of that way, which made the next download of the subscription start two ways at once.
  Turning a rule's mixed proxy off no longer clears its port.
- **Downgrade to 0.8.20:** it ignores the new options. The mixed proxy with a login is then open
  to every device that reaches its port, a rule "Only for devices" takes every device, the
  subscription is asked as podkop, without its headers, and the servers of Xray JSON or sing-box
  JSON are not read; the global check and `show_config` of 0.8.20 print the login and the headers
  unmasked. `install.sh --release` says so before it
  installs an older release.

## 0.8.20 — 2026-11-19

Engine r27, as in 0.8.19.

- **IPv6 through podkop: the setting "IPv6 traffic".** **Past podkop** (the default, as before)
  or **Through podkop**: IPv6 to the IPv6 subnets of the lists (your subnet lists, lists by link,
  community lists that have IPv6) goes by their rules as IPv4 does, from the devices of the LAN
  and from the router itself. The names of the lists are not affected: they get FakeIP IPv4
  addresses, and the server resolves them in either family. A rule needs a server with IPv6 for
  its IPv6 subnets. Devices routed whole are routed by IPv4 only. A router without IPv6 (no
  `::1`) ignores the setting and says so in the log.
- **The setting "Addresses in DNS answers"**, for names outside the lists: **Prefer IPv4** (the
  default, as since 0.8.4: an IPv6 address only for a name without IPv4), **IPv4 only** (as podkop
  0.7) or **IPv4 and IPv6** (the device chooses). The names of the lists get a FakeIP IPv4 address
  in every mode, never an IPv6 one.
- **IPv6 addresses are taken** in your subnet lists (dropped before), DNS servers and the
  bootstrap server (`[2001:4860:4860::8888]:853`, or bare without a port) and Routing Excluded IPs.
  Proxy links with `[IPv6]:port` were taken already.
- **Global check:** a section on IPv6 (the router's IPv6, the two settings, the inbound and the
  routing of IPv6, a DHCP section that relays the provider's IPv6 DNS server to the devices), and
  the chains of other programs that write the conntrack mark.
- **Fixed: Tailscale with the BitTorrent setting.** With Tailscale 1.96 or newer (OpenWrt 25.12
  ships 1.104) and BitTorrent set to anything but "As the other traffic", UDP through podkop (QUIC,
  calls, games) lost most of its packets: Tailscale copies one byte of a connection's conntrack mark
  into the packet mark, writing the whole mark, and podkop kept its BitTorrent bits in that byte.
  They are elsewhere now. On the stand with Tailscale's rules: 1 of 12 UDP datagrams came back
  through the proxy with 0.8.19, 12 of 12 now.
- **Fixed: the routing mark of an interface source** (for pbr): the connections of such a source to
  the subnets of the lists came back into podkop, since the source's mark takes the place of
  podkop's own. They go out now; a mark with podkop's bits (0x100000, 0x400000) is refused.
- **Fixed: the dashboard took part of the page's width.** In most themes (Bootstrap, OpenWrt2020,
  Argon, Aurora and others built the same way) the dashboard of 0.8.19 was as wide as its content,
  not as the page: with short server names it took two thirds to three quarters of a desktop
  screen, its right side empty. It now takes the whole width in every theme, and so does the
  diagnostics tab (narrow on a tablet the same way, in earlier versions too).
- **Install script** (already on the site since 0.8.19 came out): the output of every command is
  shown as it comes, with download progress; a silent command gets a "still waiting" line every
  30 s and, after a minute, what to check. `--no-ru` installs without the Russian translation and
  without the question, `--ru` with it.

## 0.8.19 — 2026-11-19

Engine r27.

- **Dashboard on phones and in other themes.** The BitTorrent card was a table that did not fit: on
  a phone its last column (sent) was out of sight, and in the themes Aurora and Argon it widened
  the whole dashboard past the screen. Its rows now wrap: where it is narrow, the numbers go under
  the name. "Sent" comes first, and there is a total. The grids of the dashboard follow its own
  width, not the window's. Checked in Bootstrap, Material, OpenWrt2020, Argon and Aurora, from 360
  to 1280 px.
- **BitTorrent statistics for a client that seeds.** Connections from outside (a port forward,
  UPnP) were counted only when the client answered with a plaintext handshake: encrypted ones
  never, and with flow offloading none. They are counted from their first packet now; on the stand
  the card matched the capture for plain, encrypted and uTP connections, with software flow
  offloading on and off. After a
  restart of podkop, connections already open count from then on, not with their whole life.
- **BitTorrent, clients that hide (new, off by default):** "Find clients that hide", for Block and
  "Through the servers of a rule" on the whole LAN. A client with no DHT, uTP and peer exchange and
  with encryption required went through the block of the whole LAN untouched. A device that opens
  connections to many new addresses on uncommon ports at once now has its connections checked;
  after three confirmed handshakes it is treated as a client and its earlier connections are
  closed. On the stand (containers) clients set up this way downloaded nothing under Block; aria2
  also with software flow offloading. Hardware offloading and real routers were not tested. Not
  found: a download whose tracker names about 20 peers or fewer, and connections that peers open
  to such a client from outside. An I2P router is taken for BitTorrent.
- **BitTorrent, a client on the router itself (new):** "Torrent clients on the router itself"
  names the user the client runs as (`transmission`, `aria2`); all the traffic of that user
  follows the mode. Before, the modes did not reach the router's own programs.
- **BitTorrent, fixes from the review of 0.8.9–0.8.18:**
  - with BitTorrent on and 5 to 7 groups of ports in the lists, the firewall table failed to load
    ("no buffer space available");
  - in Block, a device not seen before with a client set up by hand passed 2–3 MB before it was
    told: it is judged at its third handshake at once;
  - a tracker's answer that named a site's address on port 443 sent the devices' HTTPS to it past
    the proxy, or dropped it in Block: a peer on such a port is taken by its handshake only;
  - 3 of 65536 DNS queries looked like a uTP connect and made their device a client;
  - SIP over TCP and PostgreSQL without TLS on a device running a client were taken for
    BitTorrent;
  - a seeding client's announces to an HTTP tracker went through the rule's server; the peers of
    an announce to a known tracker are now learned from its reply;
  - the detector's sets have sizes (about 9 MB of kernel memory at most, 30–45 MB before); a full
    set is told on the dashboard and in the global check; packets with made-up source addresses no
    longer make devices.
- **A rule chosen for BitTorrent that is switched off or deleted:** BitTorrent then goes as the
  other traffic, and only the log said so. The selector marks such a rule, the field warns, and
  the dashboard card says why.
- **"Find a mask" and the block detector:** an answer of any length no longer fills memory; a
  failed search no longer stays "running".
- **Guide:** a BitTorrent chapter, with what it cannot do.

## 0.8.18 — 2026-11-17

Engine r27.

- **BitTorrent, clients set up by hand** (uTP off, encryption required, no DHT, an HTTPS
  tracker): their connections to peers in your lists went through the rule's server in "Past
  podkop". Fixed in three places:
  - the encrypted handshake is confirmed even when the client sends its third message late, as
    Transmission and qBittorrent do;
  - a connection opened before podkop knew the device runs a client is checked as well, and is
    taken as BitTorrent once it knows;
  - three confirmed handshakes with different peers are enough to tell such a device.
- **BitTorrent, trackers:** an HTTP tracker on an uncommon port is BitTorrent from the device's next
  announce on, as UDP trackers are. A connection to the router's own address is never taken for
  a peer.
- **BitTorrent statistics:** connections podkop does not handle are no longer shown as "through
  sing-box". The dashboard tells checks with no answer from the other side, and has **Reset**.
  The global check warns when the DHT and the UDP trackers get no answer at all.
- **For testers:** `podkop bittorrent_record [minutes] --reset` writes a report of the router, CPU,
  memory and BitTorrent traffic with no addresses in it. The debug log gives the reason of every
  check. A restart of podkop keeps the devices, peers and trackers it knew.
- **Issue form:** fields for the global check and the BitTorrent report.

## 0.8.17 — 2026-11-17

Engine r27.

- **BitTorrent, rebuilt.** The router decides about a client's connection by its first packet.
  What it cannot tell goes through podkop's own module in sing-box: the module learns the peers
  from the answers of trackers and the DHT before the client gets them, and it checks connections to
  uncommon ports by the encrypted BitTorrent handshake. With "Past podkop" in our tests, aria2,
  Transmission and rTorrent went 99.9–100 % straight to their peers (0.8.16: aria2 2.4 %,
  rTorrent 0 %).
- **BitTorrent, Block:** connections of other programs are no longer cut by the look of their first
  data. 0.8.16 cut Shadowsocks 2022, VMess, obfs4 and others.
- **BitTorrent, through a rule:** can also apply to the whole LAN (the new field "Whose BitTorrent
  goes through the rule").
- **BitTorrent statistics** on the Dashboard and in the Global check: traffic by kind (DHT, uTP,
  TCP, incoming) and by the way it went. The router's own counters are read every 5 s.
  `podkop bittorrent_stats` gives the same as JSON.
- **Limits:** IPv4 only. aria2 makes a closed encrypted connection again without encryption; with
  "Past podkop" the provider then sees plain BitTorrent.

## 0.8.16 — 2026-11-15

Engine r27.

- **BitTorrent:** a new setting for the BitTorrent traffic that podkop would take: "Past podkop",
  "Block" (only what podkop takes, or the whole LAN) or "Through the servers of a rule". New
  dependency: `kmod-nf-conntrack-netlink`.
- **Server choice:** "Fastest, avoiding loss" and "Balance between the best" count the loss of
  Hysteria2 and TUIC servers by the packets of their QUIC connection. Before, these servers were
  chosen by their delay alone.
- **Fixed:** port forwarding to a device in Fully Routed IPs.

## 0.8.15 — 2026-11-14

Engine r26.

- **Downloads:** when lists and subscriptions do not come directly, they come through the servers
  of the rules. The way that worked last time is tried first, and at most three ways run at once.
  In our tests a list came in 12 s; 0.8.14 had not got it after 180 s.
- **Servers:** a source can be kept out of downloads ("Do not use for downloading lists and
  subscriptions").
- **Treatments against a block:** a mask in a server's own link no longer stops the settings from
  applying, and a treatment no longer goes through a server that is itself connected through
  another one.
- **Block detector:** finds a Shadowsocks limit also when the cut falls inside an encrypted chunk.
- **Engine r26:** hysteria2 uses 34 % less CPU per gigabyte on routers without AES (MT7621); DNS
  uses less CPU per query.

## 0.8.14 — 2026-11-12

Engine r25.

- **Treatments:** "Find a mask" also tries names from public whitelists. Their addresses are in
  Settings ("Addresses of the lists of masks").
- **Lists:** they download by themselves, directly and then through the servers of the first three
  rules. The setting "Download Lists via Proxy/VPN" is gone.
- **Dashboard:** "Test latency" shows its result next to the median.
- **Fixed:** "Connect through <server>" through a server of the same subscription. A mask is no
  longer offered for a server without TLS.
- **Engine r25:** after one server of a DNS group times out, the group asks the rest at once.

## 0.8.13 — 2026-11-12

Engine r24.

- **Treatments against a block, per server.** The check window offers a treatment that fits the
  verdict: a mask of a whitelisted site for "limit", a split ClientHello for "freeze", "Connect
  through <server>" for "no path from here". A treatment is tied to the server, not to its name,
  and is kept in `/etc/config/podkop` (`cure` sections).
- **Engine r24:** `fragment` and `record_fragment` now work on REALITY (before, they were silently
  ignored).

## 0.8.12 — 2026-11-07

Engine r23 (not published as a podkop-engine release; its changes are in r24).

- **Recovery:** the separate guard service is gone. procd restarts a backend that crashed. From the
  fourth crash in a row, the router gets its own DNS back and the backend is tried again after 1,
  2, 4 … 60 minutes.
- **dnsmasq:** forwardings for single domains (for Tailscale, `/ts.net/100.100.100.100`) are kept.
  The global check warns when a forwarded domain is also in podkop's lists.
- **Subscriptions:** a provider that does not answer is reported in one line.

## 0.8.11 — 2026-11-06

Engine r23 (not published as a podkop-engine release; its changes are in r24).

- **Server choice of a rule** ("Extra" tab): "Fastest"; "Fastest, avoiding loss" (small
  downloads through the servers measure their loss); "Balance between the best" (devices are
  spread over the best servers). The loss is shown on the dashboard. The global check has a
  "Server choice" section.
- **Subscriptions:** "Update now". The update interval a provider asks for applies at once.
- **Names:** the log, YACD and the global check show the names of servers and rules instead of
  src1/src2.

## 0.8.10 — 2026-11-04

Engine r22 (not published as a podkop-engine release; its changes are in r24).

- **DNS after a reboot:** dnsmasq is set to ask podkop before it starts. If dnsmasq runs with
  settings other than the ones written for it, it is restarted.
- **Server check:** five default URLs in turn, one round a minute. The delay is the median over a
  full cycle, so one stray test does not switch the server. This makes about 3 times more check
  traffic (around 24 MB a day per active server).
- **Servers tab:** sources are reordered by dragging. The window of a subscription can copy the
  links of its servers.

## 0.8.9 — 2026-11-03

Engine r21.

- **Block detector:** a server that does not work gets a chip with the cause ("no answer",
  "freeze", "limit", "no path", "refused" …). "Check server" names the kind of block. The detector
  only shows; it changes no route.
- **Dashboard:** the servers of a rule are shown in tiers (fastest, fallback 1, fallback 2 …).
  "Back to automatic choice" removes a pin.
- **DNS:** several servers (DoH, DoT, UDP, the provider's DNS), asked in their order or fastest
  first. A server that goes silent is set aside.
- **Diagnostics:** only the server each rule uses is tested (0.3 s instead of 12 s in our tests).
- **Fixed:** XHTTP links with JSON in `extra`; ws and httpupgrade hanging on a silent server.

## 0.8.8 — 2026-10-30

Engine r20.

- **Servers apart from rules.** The "Servers" tab holds sources: subscriptions, links, outbound
  JSON, interfaces. In the "Rules" tab, a rule takes servers from sources, filtered by words in
  their names, optionally "Through" another source. Groups are gone.
- **Fallback:** rows in order (another source, "Directly", "Block") for when no server of the rule
  answers.
- **Server check:** one check for all rules, at most 4 tests at once on the router.
- **Upgrade:** the settings of podkop 0.7 and of podkop-exp up to 0.8.7 are converted. The old file
  stays as `/etc/config/podkop.pre-0.8.8`.

## 0.8.7 — 2026-10-29

Engine r19.

- **Subscriptions without cut connections:** a change of a subscription no longer restarts
  sing-box. A replaced server is closed when no connection uses it, and at the latest a day later.
- **Subscription downloads:** a slow way gets a second way beside it. "Load" waits up to a minute
  and shows each way. Errors are clear. The provider's traffic, end date and notices are shown.
- **Fixed:** a placeholder list (every server 0.0.0.0) no longer replaces the working one.

## 0.8.6 — 2026-10-28

Engine r18.

- **Fixed** in the subscriptions and groups of 0.8.5: the page did not open on OpenWrt 25.12 with
  a group and no subscription; entries could not be added on a fresh install; a subscription added
  after Load is downloaded again 10 s later (it waited up to 12 hours). Removing the package also removes the subscription lists.

## 0.8.5 — 2026-10-27

Engine r18.

- **Subscriptions and groups.** The router downloads a subscription itself, directly or through
  its own servers. The device identifier (HWID) comes from the router's hardware. The list is kept
  on the router, so rules work at a start without the network.
- **Lists:** their content lives in files beside cache.db. Big lists are updated one at a time.
- **Clock:** when the router's time is wrong, podkop helps NTP and checks the time over HTTPS.
- **Global check:** suggests an MTU for a VPN section whose check fails.

## 0.8.4 — 2026-10-25

Engine r17.

- **uTLS fallback, on by default:** the fingerprint without X25519MLKEM768 is tried first, then
  firefox, then the fingerprint as it is. The choice is remembered for a server for a day.
- **IPv6-only sites open:** an IPv6 address is given when a name has no IPv4 address.
- **Fixed:** with Tailscale, connections of LAN devices through the proxy no longer hang.

## 0.8.3 — 2026-10-24

Engine r16.

- **Connect through:** a section can connect through another one (a proxy through a proxy, a group
  or a VPN).
- **mwan3:** the DNS fallback asks the provider of every uplink. Connections bound to a WAN work.
  A start that failed is retried.
- **YACD** comes in the package; a button in YACD itself upgrades it.
- **Memory:** a million subnets and 500 thousand domains take 151 MB instead of 251 MB.
- **Installer:** downloads through the GitHub API (OpenWrt's wget hung on github.com links).
- 0.8.2 was withdrawn after about an hour: its form wrongly reported a loop when a VPN section was
  chosen in "Connect through". 0.8.3 fixes it.

## 0.8.1 — 2026-10-23

Engine r15.

- **Page:** the running backend answers its commands, so the page barely loads the router.
- **Proxy links** are checked before a save.
- **sing-box is not bound to an interface:** mwan3 and routes to single hosts work.
- **Interface fields** take a network (wan, lan, guest) or a PPPoE port.
- **YACD** opens only from the chosen devices.

## 0.8.0 — 2026-10-20

Engine r15.

- First release: podkop 0.7.24 with a backend written in Go and sing-box (podkop-engine) inside.
  It uses podkop's settings and LuCI page.
