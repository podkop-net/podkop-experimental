# Changelog

[Русский](CHANGELOG.ru.md)

What changed in each release of podkop-exp, newest first. The engine is the sing-box build
[podkop-engine](https://github.com/podkop-net/podkop-engine) the release has inside. The full
notes, with the measurements and the limits, are on the
[releases page](https://github.com/podkop-net/podkop-experimental/releases).

## 0.8.18 — 2026-11-18

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
