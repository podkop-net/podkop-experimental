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
  rows: BitTorrentTableRow[];
  blocked: string[];
  notes: string[];
}

export function bitTorrentKindName(kind: Podkop.BitTorrentKind): string {
  switch (kind) {
    case 'discovery':
      return _('DHT and UDP trackers');
    case 'utp':
      return _('uTP');
    case 'tcp':
      return _('TCP to peers');
    case 'late':
      return _('TCP told by its handshake in podkop');
    case 'checked':
      return _('TCP to uncommon ports, checked');
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
  const blocked = (report.blocked || []).map((item) =>
    _('%s: %d packets (%s) dropped').format(
      bitTorrentKindName(item.kind),
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
  const module = report.module;
  if (module) {
    notes.push(
      _('Peers learned: %d from %d replies and %d announces').format(
        module.learned ?? 0,
        module.replies ?? 0,
        module.announces ?? 0,
      ),
    );
    if ((module.watched ?? 0) > 0) {
      notes.push(
        _(
          'Connections checked: %d; confirmed as BitTorrent: %d (closed: %d, left open: %d); not BitTorrent: %d',
        ).format(
          module.watched ?? 0,
          module.confirmed ?? 0,
          (module.rejected ?? 0) + (module.reset ?? 0),
          module.kept_open ?? 0,
          (module.not_shaped ?? 0) +
            (module.refuted ?? 0) +
            (module.far_first ?? 0),
        ),
      );
    }
  }
  return {
    mode: bitTorrentModeName(report),
    since: spanText(report.since),
    rows,
    blocked,
    notes,
  };
}
