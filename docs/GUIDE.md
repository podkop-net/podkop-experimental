# User guide

[Русский](GUIDE.ru.md)

The page is in LuCI under **Services → Podkop**. It has five tabs: Servers, Rules, Settings,
Diagnostics and Dashboard. Changes take effect after **Save & Apply**. Most fields have a hint
under them; this guide covers what the hints do not.

- [First start](#first-start)
- [Servers](#servers)
- [Rules](#rules)
  - [Mixed proxy](#mixed-proxy)
- [Settings](#settings)
- [BitTorrent](#bittorrent)
- [IPv6](#ipv6)
- [Dashboard](#dashboard)
- [Diagnostics](#diagnostics)
- [When something does not work](#when-something-does-not-work)
- [Upgrade](#upgrade)
- [Command line](#command-line)

## First start

1. **Servers** tab: paste a subscription address or a server link into the empty source `src1`.
   The type of the source is recognized from the text.
2. Press **Save & Apply**. The rule `main` (the community lists Russia inside, Discord and
   Telegram) already takes its servers from `src1`.
3. Open **Dashboard**. The tile of the server the rule uses is highlighted.

Until a source is filled in, podkop changes nothing on the router.

## Servers

A source is one of:

- a **subscription**: the address of a provider. **Load** shows its servers before you save.
  After Save & Apply the router downloads the list itself and keeps it, so the rules also work
  at a start without the network. The window of a subscription shows its state, the provider's
  traffic and end date, and has **Update now** and buttons to copy the links;
- one or more **server links** (`vless://`, `ss://`, `trojan://`, `hy2://` …; see the
  [examples](../String-example.md));
- an **outbound JSON** of sing-box;
- an **interface**: a tunnel set up on the router (WireGuard, AmneziaWG …), a modem or a second WAN.

**User-Agent** and **Extra headers** of a subscription: some providers give the list only to the
apps they name, and send podkop a web page or notes like "open this link in the app". Type the
app's name alone, without a version, in User-Agent (for example `INCY`) and press **Load**: the
window says so when the provider sends that name JSON or YAML, which podkop cannot read yet, a web
page or notes, and a list in use stays in use. The router still sends its own device identifier
(HWID), so it takes its own place among the subscription's devices: the HWID and the other device
headers, the client's address (`X-Forwarded-For` …) and the headers of the connection cannot be
set. Extra headers (`Name: value`, one a line) are for a key the provider asks for: the global
check shows their names only, and they go to the host of the subscription address only, not to
another host it redirects to. The User-Agent is the name of an app, not a secret: the global check
shows it.

The order of the sources (drag ☰) changes nothing but the view. **Do not use for downloading
lists and subscriptions** keeps a source out of downloads. Use it for a subscription with little
traffic, or a tunnel into a closed network.

## Rules

A rule says which sites go through which servers. When a site is in several rules, the upper rule
wins; drag ☰ to change the order. A rule has four tabs:

- **Main**: the lists of the rule. They can be community lists, your own domains and subnets (a
  **Dynamic List** or a **Text List**), lists by link, and **Fully Routed IPs**: devices whose whole IPv4 traffic goes
  by this rule. Subnets may be IPv6 (see [IPv6](#ipv6)); devices routed whole are IPv4 addresses.
  **Only for devices** limits the rule to some devices: see [A rule for some devices](#a-rule-for-some-devices).
- **Servers**: one or more rows. A row is a source with optional filters. **Name contains** and
  **Name does not contain** match the start of a word, so `NL` finds `NL-1` and `Amsterdam NL` but
  not `RU2NL`. The **Through** column connects to the row's servers via another source. A row can
  also be **Directly** (an exclusion) or **Block**.
- **Fallback**: rows in order. They are used when no server of the rule answers. With **Block**
  as a fallback, the rule goes back to its servers soon after the network returns.
- **Extra**: the server choice and the rule's mixed proxy (SOCKS5 and HTTP on a port of the
  router, see [Mixed proxy](#mixed-proxy)).

Server choice:

| Mode | How the server is chosen | Cost |
|---|---|---|
| Fastest | the lowest median delay of the server checks; it switches only to a server faster by the tolerance (Settings) | the checks only |
| Fastest, avoiding loss | the delay weighed by the loss that downloads of 256 KB count, through the server in use and the three next best | about 50 MB a day per rule at the default 30 minutes |
| Balance between the best | devices are spread over the best servers and keep theirs; a server with high loss gets no devices | about 60 MB a day per rule (five servers checked) |

### A rule for some devices

**Only for devices** (tab Main) makes a rule take the traffic of the devices listed there, IPv4 or
IPv6 addresses and subnets, and of no other. The other devices are not taken by it: they go on to
the rules below, and directly when no rule takes them.

Example: YouTube through the servers on the TV only, blocked on the other devices.

1. Rule "TV": the community list YouTube, **Only for devices**: the TV's address, your servers.
2. Below it, rule "No YouTube": the community list YouTube, the server row **Block**.

The order matters: a rule above that takes the same list for every device takes the TV too. The
Lists column of the grid tells it ("… is in the rule … above, for its devices only").

- The field goes by address: a device that takes another's address is that device for the rule.
  It is no lock.
- Give the device a fixed address first, a static lease (a static DHCP address): with a new
  address it is another device for the rule. A phone or a laptop with a private (rotating) Wi-Fi
  address gets a new MAC address, and with it a new lease: turn that off for your network on the
  device.
- The DNS answers are the same for every device: the router's DNS cannot tell them apart. The
  other devices also get FakeIP addresses for the names of the list, and no IPv6 address for them
  (with **IPv4 and IPv6** in the DNS answers they lose IPv6 for those names). podkop sends their
  connections out directly through sing-box, which opens them anew from the router: they are not
  offloaded, **Disable QUIC** applies to them for those names, and per-device firewall rules
  (time limits), pbr or mwan3 rules by source address, SQM per IP and nlbwmon no longer see them
  as that device's traffic.
- The **Fully Routed IPs** of such a rule must be among its devices; the page refuses others. The
  **Fully Routed IPs** of every rule and the **Routing Excluded IPs** come before it: a device
  routed whole by another rule, or excluded, is not taken by it (the grid tells it).
- IPv6: a device's IPv6 addresses change (privacy addresses), so an IPv6 address in the field
  works only for a fixed one. It matters only with **IPv6 traffic: Through podkop** and IPv6
  subnets in the lists; the names of the lists always go over IPv4. A unique local address
  (`fd…`) is a device's source to the internet only when it has no global IPv6 address and the
  router translates its IPv6 (NAT66); a link-local one (`fe80::…`) never is, and the page refuses it.
- The mixed proxy of the rule stays open to every device of the LAN. The BitTorrent modes do not
  see the field (see [BitTorrent](#bittorrent)).
- The router's own traffic is normally not taken: its source is the router's WAN address. It is
  taken when that address is among the devices (a router behind another router, with a listed
  subnet that holds its WAN address), and for IPv6 when the WAN has no IPv6 address of its own:
  the router then sends from its LAN address.
- A change of the field restarts sing-box, as a change of a rule's lists does: open connections
  are dropped.
- An older version of podkop does not know the field: the rule there takes every device.
- Which rules take a device that cannot open the page (a TV): `podkop device 192.168.1.50` on the
  router lists them in their order. The global check names the devices of each such rule (the
  IPv4 ones; the IPv6 ones are counted), and under **This device** tells whether the IPv4 address
  of the device that runs it is among them.

### Mixed proxy

A rule can open a proxy on the router: SOCKS5 and HTTP on one port of the LAN address
(**Extra → Enable Mixed Proxy**). What an app sends there goes through the servers of the rule.

**User name and password.** Without them, every device that reaches the port can use it, a
program on a device of your LAN included. With both set, an app must sign in: SOCKS5 with the
user name and password, HTTP with Basic authentication. SOCKS4 has no password and is refused
then. **Generate** fills in a random password of 16 letters and digits (and the user name
`podkop` when there is none); a password typed by hand needs at least 8 characters. Both empty
is the proxy without a login, as before 0.8.21.

- The login travels unencrypted, like the app's traffic to the router. It keeps strangers and
  programs of your LAN off the port; it does not make a port forwarded from the internet safe.
  To use the proxy from outside, connect to the router over a VPN (WireGuard).
- In a proxy address the login is written `socks5h://user:password@192.168.1.1:2080` or
  `http://user:password@192.168.1.1:2080`. A sign of the password other than letters, digits and
  `-._~` is written as `%` and its code (`@` is `%40`); generated passwords have none.
- Browsers have no fields for a SOCKS5 login (Chrome cannot use one at all): set the browser to
  the HTTP proxy at the same address and port, and it asks for the login.
- The login stays in the settings while the proxy is off. The global check, `show_config` and
  `show_sing_box_config` mask it; the global check tells for each proxy whether it listens and
  whether it asks for a login.
- A wrong password typed in an app is written by sing-box as it came to the system log
  (`logread`) and to YACD's log; podkop's log (**View logs**, `podkop check_logs`) hides it.

## Settings

The tab is one list; here its fields are grouped by topic.

| Fields | What they set |
|---|---|
| DNS servers | rows of DoH, DoT, UDP or **The provider's DNS**, asked **in their order** or **the fastest first** (an IPv6 server as `[2001:4860:4860::8888]:853`); the bootstrap DNS; the TTL podkop gives in its answers |
| Addresses in DNS answers | for names outside the lists: **Prefer IPv4** (an IPv6 address only for a name without IPv4), **IPv4 only**, or **IPv4 and IPv6**. See [IPv6](#ipv6) |
| IPv6 traffic | **Past podkop** or **Through podkop**. See [IPv6](#ipv6) |
| Server check | the URLs, the interval and the tolerance of the delay checks of every rule; the download check |
| uTLS-fallback | on by default: the link's fingerprint is tried first without the X25519MLKEM768 key share, then firefox, then as it is; the first that passes is kept for the server and checked again once a day |
| BitTorrent | **As the other traffic**, **Past podkop**, **Block** or **Through the servers of a rule**; the last two apply to what podkop takes or to the whole LAN. See [BitTorrent](#bittorrent) |
| Public lists of masks | where "Find a mask" takes the names of whitelisted sites |
| Interfaces | the LAN interface podkop serves, and an output interface for its own connections |
| YACD | the YACD dashboard: on or off, the interfaces it opens from, its key |
| Other | Disable QUIC, the update interval of the lists, Dont Touch My DHCP!, the cache file, the log level, Exclude NTP, IPs excluded from routing |

## BitTorrent

Settings → **BitTorrent** says what happens to the traffic of torrent clients.

| Mode | What it does |
|---|---|
| As the other traffic | nothing special: the rules decide, as for any program |
| Past podkop | torrents go straight to the internet, not through your servers (the exceptions are below), and the router can offload them |
| Block | dropped |
| Through the servers of a rule | sent to the servers of the rule you choose, for example ones without a data cap |

**Block** and **Through the servers of a rule** act on what podkop takes (the devices routed whole
and the addresses of the lists) or on the **whole LAN**.

A client is told by the first packets of the DHT, of uTP and of trackers, by the BitTorrent
handshake, by the peers a tracker or the DHT named, and, for an encrypted connection, by the shape
of its handshake.

Two more fields:

- **Find clients that hide** (for the whole LAN, off by default). A client set up without DHT, uTP
  and peer exchange, with encryption required, shows the router no sign. With this on, a device
  that opens connections to many new addresses on uncommon ports at once has its new connections
  checked. When three of them turn out to be BitTorrent, the device is treated as running a client
  and the connections it opened earlier are closed. Connections under the check go through
  sing-box and are not offloaded.
- **Torrent clients on the router itself.** The detector sees the devices of the LAN, not the
  router's own programs. Name the user the client runs as (`transmission` and `aria2` in OpenWrt's
  packages) and all the traffic of that user follows the mode. A client that speaks SOCKS5
  (qBittorrent, Deluge) can instead be pointed at the [mixed proxy](#mixed-proxy) of a rule,
  with its user name and password when the proxy has a login (qBittorrent: *Authentication*;
  Deluge: the type *Socks5 Auth*): what it sends there goes through that rule's servers,
  whatever the BitTorrent mode. Transmission and aria2 have no proxy setting for peers.

What it cannot do:

- **IPv6** is not looked at.
- **A client that never connects again.** An encrypted connection is recognised only after it is
  open; podkop then closes it so that the client opens it again, the right way. rTorrent and aria2
  with encryption required rarely do: in "Past podkop" and "Through the servers of a rule" such
  connections stay on the route they had, for peers that no tracker or DHT answer named.
- **A small download** from a client that hides is not found on the whole LAN: three encrypted
  handshakes must complete, and most addresses a tracker names do not answer. In our tests a
  tracker's answer of 50 peers was enough, one of 20 or fewer was not.
- **A client that hides and has an open port** (a port forward, UPnP): what it opens itself is
  blocked, but connections that peers open to it from outside are not.
- **Programs that look alike.** An I2P router is taken for BitTorrent. A proxy client whose
  connections look random from the first byte (shadowsocks-rust, V2Ray's VMess) is taken for a
  torrent client when it keeps connections to three or more servers on uncommon ports; on a device
  that also runs a torrent client, one such connection is enough.
- **Flow offloading.** A connection the router offloaded passes no rule. Podkop decides by the
  first packet wherever it can. On the whole LAN, a client whose only sign is in the data of a TCP
  connection (a plain-HTTP tracker, a plaintext handshake) is not told with offloading on, unless
  "Find clients that hide" catches it. That setting was tested with software offloading only, not
  with hardware offloading or on real routers yet.
- **A client on the router that runs as root**, and programs behind an interface that is not among
  the source interfaces, are not seen. With **Block**, the web interface of a client on the router
  answers only to the private addresses of the LAN.
- **The first announce** to an HTTP tracker of your lists, and every announce to an HTTPS tracker,
  go by the rules, like any site.
- **Only for devices** of a rule is not seen: **Block** and **Through the servers of a rule** act on
  the addresses of the lists for every device.

## IPv6

podkop gives the names of the lists FakeIP addresses of IPv4, in every mode: a device reaches
such a site over IPv4 through the rule's server, and the server resolves the name itself, in
IPv4 or IPv6. What the settings change is the rest:

- **Addresses in DNS answers** is what the devices and the router get for names outside the lists.
  With **IPv4 and IPv6**, a device with IPv6 usually picks IPv6 for such sites; they go past podkop
  as their IPv4 does.
- **IPv6 traffic, Through podkop** sends IPv6 to the IPv6 subnets of the lists (Telegram, for
  example, has IPv6 data centres; an app may connect to them without asking the DNS) by their rules,
  as IPv4. The servers of such a rule need IPv6: a server without it fails those connections, and
  the log of podkop says so. **Past podkop** leaves IPv6 alone, as before 0.8.20.

What it does not do: devices routed whole (Fully Routed IPs) are routed by their IPv4 only; the
BitTorrent setting looks at IPv4 only; FakeIP has no IPv6 addresses, so a device with IPv6 only
gets no address for a name of a list. A router whose provider gives IPv6 in relay mode passes the
provider's DNS server on to the devices: they then ask it, not podkop, and the global check warns
of it (give them the router's DNS server in the DHCP settings of the LAN).

## Dashboard

- The tile of the server a rule uses is highlighted. With several servers, a line under the
  rule's name also says how it was chosen: the automatic choice, a fallback, or **Manual**. The
  servers are shown as tiles, in tiers: the fastest, then fallback 1,
  fallback 2 …
- A tile shows the delay. With a loss mode it also shows the loss (`~` while the checks are
  few) and the devices in the balance (`⇄N`).
- Click a tile to pin that server. **Back to automatic choice** removes the pin. **Test latency**
  tests the servers now and shows the result next to the median. For a rule of several servers it
  is a round of the server check, as the rule's own rounds go (each server with the URL of the
  round, the next one when that does not answer), and the result is the new median. A rule of one
  server has it tested alone: with the first server check URL, the next one when that does not
  answer.
- A server that does not work gets a chip with the cause: no answer, freeze, limit, no path,
  refused and others. **Check server** (or **Check problem servers**) probes the server and names
  the kind of block. The window can offer a **Treatment for this server**:

  | Verdict | Treatment |
  |---|---|
  | limit (connections cut after about 16–20 KB) | a mask: a forged TLS hello of a whitelisted site goes first. **Find a mask** looks for a name that works on this server |
  | freeze | the TLS hello is split into two records, or the uTLS fallback |
  | no path | connect through the server the check reached it through |

  A treatment belongs to the server and survives a rename. A mark on the tile opens the window,
  where the treatment can be removed.
- The **BitTorrent** card (when BitTorrent is not "As the other traffic") shows the traffic of
  BitTorrent clients: by kind (DHT and trackers, uTP, TCP, incoming) and by the way it went, with
  what the devices sent and received, the connections, and a total. The router counts IPv4 with
  packet headers, so the numbers are a little over the client's own. Connections from outside (a
  port forward) are counted when the client listens on the port its DHT or uTP uses. With hardware
  offloading on a chip that does not report bytes per connection, offloaded connections may show
  their first packets only. **Reset** starts the counts again, without a restart of podkop.

## Diagnostics

- **Run Diagnostic** checks DNS, sing-box, the firewall rules, FakeIP and the servers that the
  rules use now, each with the first server check URL, the next one when that does not answer.
  Without a proxy it asks all the server check URLs at once and shows their median; a URL that
  does not answer is named (the provider may block it). The global check does the same.
- **Get global check** puts everything into one report, with keys and passwords masked. This is
  the report to attach to an issue. The addresses of the LAN are not masked: the settings in it
  show the devices of the rules, IPv6 ones too.
- **View logs** and **Show sing-box config** show the log and the configuration that runs.
- Restart, stop, start, and autostart on or off.

## When something does not work

1. Diagnostics → **Run Diagnostic**. A failed line says what fails.
2. **Get global check**. It also covers the router's clock, whether dnsmasq runs with the settings
   written for it, the server choice and BitTorrent.
3. A server marked on the dashboard: **Check server**, then the treatment it offers.
4. A subscription does not come: its window tells which ways were tried and why each failed. For
   the lists, `podkop list_status` shows the last error of each.
5. A rule for some devices does not take a device: `podkop device <its address>` on the router
   lists the rules that take it, in their order; on the device itself, **This device** of the
   global check tells whether its IPv4 address is among the rule's devices.
6. Still not working: open an [issue](https://github.com/podkop-net/podkop-experimental/issues)
   with the global check and what you did. The log is `logread -e podkop`.
7. BitTorrent goes the wrong way: run `podkop bittorrent_record 10 --reset`, start the download,
   and attach the file it names after 10 minutes. It holds counts only: no addresses or names.

## Upgrade

Run the install command of the [README](../README.md#install) again. It shows the release it
installs and the version installed now, and says so when there is nothing to do. Then clear the
browser's cache before opening the page (or open it in a private window): the browser may keep
the page of the release before.

- `--release 0.8.19` at the end of the command installs that release, an older one too (0.8.8 or
  newer). Your settings stay in the format of podkop-exp; an older release ignores the options
  added after it.
- When GitHub refuses ("GitHub refused the request": its API allows 60 requests an hour from one
  address), download the packages on a computer and use `--from`, as the README
  [says](../README.md#install-without-githubs-api).

## Command line

| Command | What it does |
|---|---|
| `podkop global_check` | the global check |
| `podkop check_logs` | the log of the backend and of sing-box |
| `podkop show_config`, `podkop show_sing_box_config` | the settings and the running sing-box configuration, secrets masked |
| `podkop reload` | apply the settings again and tell the result |
| `podkop device <address>` | the rules that take the traffic of the device of that address, in their order |
| `podkop list_update` | download every list now |
| `podkop subscription_update [name]` | download a subscription (or all) now |
| `podkop bittorrent_stats` | the BitTorrent statistics as JSON |
| `podkop bittorrent_reset` | start the BitTorrent statistics again |
| `podkop bittorrent_record [minutes] [--reset]` | a report of BitTorrent for a test: a sample every 10 s (default 10 minutes), no addresses |
| `service podkop restart` | restart the service |

`podkop` without arguments lists every command.
