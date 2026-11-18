import type { Podkop } from '../../../types';
import { prettyBytes } from '../../../../helpers/prettyBytes';

// The dashboard's table of BitTorrent: what the backend's report (the method bittorrent) came to,
// a line for each kind of traffic and the way the mode sent it, then what the mode blocked and
// what the module of sing-box did. The backend reads the router's counters of the connections
// every 5 s (btstats.PollEvery).

export interface BitTorrentTableRow {
  kind: string;
  way: string;
  open: string;
  connections: string;
  received: string;
  sent: string;
  // the packets, for the hint of the row
  packets: string;
}

export interface BitTorrentTable {
  mode: string;
  since: string;
  // the statistics were reset (the button), not counted from the start of the mode
  reset: boolean;
  rows: BitTorrentTableRow[];
  // what the rows add up to; none with fewer than two rows
  total?: BitTorrentTableRow;
  blocked: string[];
  notes: string[];
  // what the numbers are, under the table
  caption: string;
}

export function bitTorrentKindName(kind: Podkop.BitTorrentKind): string {
  switch (kind) {
    case 'discovery':
      return _('DHT and trackers');
    case 'utp':
      // the DHT of a socket that speaks uTP is counted with it (the firewall's bt_discovery)
      return _('uTP and the DHT of its socket');
    case 'tcp':
      return _('TCP to peers');
    case 'late':
      return _('TCP told by its handshake in podkop');
    case 'checked':
      return _('TCP to uncommon ports');
    case 'incoming':
      return _('Incoming through a port forward');
  }
  return kind;
}

export function bitTorrentWayName(
  way: Podkop.BitTorrentWay,
  rule?: string,
): string {
  switch (way) {
    case 'relay':
      return _('Through sing-box, straight out');
    case 'past':
      return _('Past podkop');
    case 'untouched':
      return _('Not through podkop');
    case 'rule':
      return _('Through the rule %s').format(rule || '');
    case 'checked':
      return _('Through sing-box, being checked');
    case 'blocked':
      return _('Blocked');
  }
  return way;
}

export function bitTorrentModeName(report: Podkop.BitTorrentReport): string {
  const scope = report.lan
    ? _('On the whole LAN')
    : _('Only what podkop takes');
  switch (report.mode) {
    case 'bypass':
      return _('Past podkop');
    case 'block':
      return `${_('Block')} · ${scope}`;
    case 'section':
      return `${_('Through the servers of a rule')} «${report.rule || ''}» · ${scope}`;
  }
  return _('As the other traffic');
}

// spanText is a span of seconds, short
export function spanText(seconds: number): string {
  if (seconds < 60) return _('%d s').format(seconds);
  if (seconds < 3600) return _('%d min').format(Math.floor(seconds / 60));
  return _('%d h %d min').format(
    Math.floor(seconds / 3600),
    Math.floor(seconds / 60) % 60,
  );
}

// bitTorrentTable makes the table of a report; undefined when BitTorrent goes as the other
// traffic (no card).
export function bitTorrentTable(
  report: Podkop.BitTorrentReport | undefined,
): BitTorrentTable | undefined {
  if (!report || !report.mode || report.mode === 'off') return undefined;
  const rows = (report.rows || []).map((row) => ({
    kind: bitTorrentKindName(row.kind),
    way: bitTorrentWayName(row.way, report.rule),
    open: String(row.open),
    connections: String(row.connections),
    received: report.counted ? prettyBytes(row.received.bytes) : '—',
    sent: report.counted ? prettyBytes(row.sent.bytes) : '—',
    packets: _('Packets: received %d, sent %d').format(
      row.received.packets,
      row.sent.packets,
    ),
  }));
  let total: BitTorrentTableRow | undefined;
  if (rows.length > 1) {
    const sum = (pick: (row: Podkop.BitTorrentRow) => number) =>
      (report.rows || []).reduce((all, row) => all + pick(row), 0);
    total = {
      kind: _('In all'),
      way: '',
      open: String(sum((row) => row.open)),
      connections: String(sum((row) => row.connections)),
      received: report.counted
        ? prettyBytes(sum((row) => row.received.bytes))
        : '—',
      sent: report.counted ? prettyBytes(sum((row) => row.sent.bytes)) : '—',
      packets: _('Packets: received %d, sent %d').format(
        sum((row) => row.received.packets),
        sum((row) => row.sent.packets),
      ),
    };
  }
  const blocked = (report.blocked || []).map((item) =>
    _('%s: %d packets (%s) dropped').format(
      // (the block drops uTP as such: the DHT of its socket is counted with the discovery)
      item.kind === 'utp' ? _('uTP') : bitTorrentKindName(item.kind),
      item.dropped.packets,
      prettyBytes(item.dropped.bytes),
    ),
  );
  const notes: string[] = [];
  if (report.error) {
    notes.push(
      _('The last read of the connections failed: %s').format(report.error),
    );
  }
  if (!report.counted && rows.length > 0) {
    notes.push(
      _(
        'The router does not count the bytes of connections (net.netfilter.nf_conntrack_acct is 0)',
      ),
    );
  }
  if (report.utp_to_tcp?.packets > 0) {
    notes.push(
      _('uTP connects turned to TCP (on a flow of the DHT): %d').format(
        report.utp_to_tcp.packets,
      ),
    );
  }
  // what the detector could not take: its sets full (it remembers no new device, socket or
  // peer, and tells less), packets whose source address is not of their interface
  const limits = report.limits;
  const full =
    (limits?.devices ?? 0) +
    (limits?.sockets ?? 0) +
    (limits?.utp ?? 0) +
    (limits?.peers ?? 0) +
    (report.module?.set_full ?? 0);
  if (full > 0) {
    notes.push(
      _(
        'The sets of the BitTorrent detector are full, it tells less: %d packets and peers found no room',
      ).format(full),
    );
  }
  if ((limits?.foreign ?? 0) > 0) {
    notes.push(
      _(
        'Packets from addresses that do not belong to their interface, not checked for BitTorrent: %d',
      ).format(limits?.foreign ?? 0),
    );
  }
  const module = report.module;
  if (module) {
    // nothing to say of a client whose peers the firewall tells by its own packets (uTP, the
    // DHT): the module read no reply, and "0 peers learned" read as a failure
    if ((module.replies ?? 0) + (module.announces ?? 0) > 0) {
      notes.push(
        _(
          'Peers learned from the replies of trackers and of the DHT: %d (replies read: %d, announces: %d)',
        ).format(
          module.learned ?? 0,
          module.replies ?? 0,
          module.announces ?? 0,
        ),
      );
    }
    if ((module.watched ?? 0) > 0) {
      notes.push(
        _(
          'Connections checked: %d; confirmed as BitTorrent: %d (closed: %d, left open: %d); not BitTorrent: %d; no answer from the other side: %d',
        ).format(
          module.watched ?? 0,
          module.confirmed ?? 0,
          (module.rejected ?? 0) + (module.reset ?? 0),
          module.kept_open ?? 0,
          (module.not_shaped ?? 0) +
            (module.refuted ?? 0) +
            (module.far_first ?? 0),
          (module.no_data ?? 0) + (module.unanswered ?? 0),
        ),
      );
    }
  }
  // the early check: a device with no sign of a client, told by its own connections
  if (module && (module.early_confirmed ?? 0) > 0) {
    notes.push(
      _(
        'Devices with no other sign of a client: %d connections confirmed as BitTorrent, %d devices told by them',
      ).format(module.early_confirmed ?? 0, module.early_self ?? 0),
    );
  }
  return {
    mode: bitTorrentModeName(report),
    since: spanText(report.since),
    reset: (report.reset_at ?? 0) > 0,
    rows,
    total,
    blocked,
    notes,
    caption: _(
      'Sent and received as the devices of the LAN see it, counted by the router with packet headers (1 GB = 1000 MB). IPv4 only; a client on the router itself is not counted.',
    ),
  };
}
