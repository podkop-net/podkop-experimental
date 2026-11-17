# User guide

[Русский](GUIDE.ru.md)

The page is in LuCI under **Services → Podkop**. It has five tabs: Servers, Rules, Settings,
Diagnostics and Dashboard. Changes take effect after **Save & Apply**. Most fields have a hint
under them; this guide covers what the hints do not.

- [First start](#first-start)
- [Servers](#servers)
- [Rules](#rules)
- [Settings](#settings)
- [Dashboard](#dashboard)
- [Diagnostics](#diagnostics)
- [When something does not work](#when-something-does-not-work)
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

The order of the sources (drag ☰) changes nothing but the view. **Do not use for downloading
lists and subscriptions** keeps a source out of downloads. Use it for a subscription with little
traffic, or a tunnel into a closed network.

## Rules

A rule says which sites go through which servers. When a site is in several rules, the upper rule
wins; drag ☰ to change the order. A rule has four tabs:

- **Main**: the lists of the rule. They can be community lists, your own domains and subnets (a
  **Dynamic List** or a **Text List**), lists by link, and **Fully Routed IPs**: devices whose whole traffic goes
  by this rule.
- **Servers**: one or more rows. A row is a source with optional filters. **Name contains** and
  **Name does not contain** match the start of a word, so `NL` finds `NL-1` and `Amsterdam NL` but
  not `RU2NL`. The **Through** column connects to the row's servers via another source. A row can
  also be **Directly** (an exclusion) or **Block**.
- **Fallback**: rows in order. They are used when no server of the rule answers. With **Block**
  as a fallback, the rule goes back to its servers soon after the network returns.
- **Extra**: the server choice and the local mixed proxy port of the rule.

Server choice:

| Mode | How the server is chosen | Cost |
|---|---|---|
| Fastest | the lowest median delay of the server checks; it switches only to a server faster by the tolerance (Settings) | the checks only |
| Fastest, avoiding loss | the delay weighed by the loss that downloads of 256 KB count, through the server in use and the three next best | about 50 MB a day per rule at the default 30 minutes |
| Balance between the best | devices are spread over the best servers and keep theirs; a server with high loss gets no devices | about 60 MB a day per rule (five servers checked) |

## Settings

The tab is one list; here its fields are grouped by topic.

| Fields | What they set |
|---|---|
| DNS servers | rows of DoH, DoT, UDP or **The provider's DNS**, asked **in their order** or **the fastest first**; the bootstrap DNS; the TTL podkop gives in its answers |
| Server check | the URLs, the interval and the tolerance of the delay checks of every rule; the download check |
| uTLS-fallback | on by default: the link's fingerprint is tried first without the X25519MLKEM768 key share, then firefox, then as it is; the first that passes is kept for the server and checked again once a day |
| BitTorrent | **As the other traffic**, **Past podkop**, **Block** or **Through the servers of a rule**; the last two apply to what podkop takes or to the whole LAN |
| Public lists of masks | where "Find a mask" takes the names of whitelisted sites |
| Interfaces | the LAN interface podkop serves, and an output interface for its own connections |
| YACD | the YACD dashboard: on or off, the interfaces it opens from, its key |
| Other | Disable QUIC, the update interval of the lists, Dont Touch My DHCP!, the cache file, the log level, Exclude NTP, IPs excluded from routing |

## Dashboard

- The tile of the server a rule uses is highlighted. With several servers, a line under the
  rule's name also says how it was chosen: the automatic choice, a fallback, or **Manual**. The
  servers are shown as tiles, in tiers: the fastest, then fallback 1,
  fallback 2 …
- A tile shows the delay. With a loss mode it also shows the loss (`~` while the checks are
  few) and the devices in the balance (`⇄N`).
- Click a tile to pin that server. **Back to automatic choice** removes the pin. **Test latency**
  tests the servers now and shows the result next to the median.
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
  BitTorrent clients: by kind (DHT and UDP trackers, uTP, TCP, incoming) and by the way it went.
  **Reset** starts the counts again, without a restart of podkop.

## Diagnostics

- **Run Diagnostic** checks DNS, sing-box, the firewall rules, FakeIP and the servers that the
  rules use now.
- **Get global check** puts everything into one report, with keys and passwords masked. This is
  the report to attach to an issue.
- **View logs** and **Show sing-box config** show the log and the configuration that runs.
- Restart, stop, start, and autostart on or off.

## When something does not work

1. Diagnostics → **Run Diagnostic**. A failed line says what fails.
2. **Get global check**. It also covers the router's clock, whether dnsmasq runs with the settings
   written for it, the server choice and BitTorrent.
3. A server marked on the dashboard: **Check server**, then the treatment it offers.
4. A subscription does not come: its window tells which ways were tried and why each failed. For
   the lists, `podkop list_status` shows the last error of each.
5. Still not working: open an [issue](https://github.com/podkop-net/podkop-experimental/issues)
   with the global check and what you did. The log is `logread -e podkop`.
6. BitTorrent goes the wrong way: run `podkop bittorrent_record 10 --reset`, start the download,
   and attach the file it names after 10 minutes. It holds counts only: no addresses or names.

## Command line

| Command | What it does |
|---|---|
| `podkop global_check` | the global check |
| `podkop check_logs` | the log of the backend and of sing-box |
| `podkop show_config`, `podkop show_sing_box_config` | the settings and the running sing-box configuration, secrets masked |
| `podkop reload` | apply the settings again and tell the result |
| `podkop list_update` | download every list now |
| `podkop subscription_update [name]` | download a subscription (or all) now |
| `podkop bittorrent_stats` | the BitTorrent statistics as JSON |
| `podkop bittorrent_reset` | start the BitTorrent statistics again |
| `podkop bittorrent_record [minutes] [--reset]` | a report of BitTorrent for a test: a sample every 10 s (default 10 minutes), no addresses |
| `service podkop restart` | restart the service |

`podkop` without arguments lists every command.
