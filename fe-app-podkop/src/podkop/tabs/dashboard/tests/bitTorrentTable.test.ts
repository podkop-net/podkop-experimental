import { describe, expect, it } from 'vitest';
import { bitTorrentTable, spanText } from '../helpers/bitTorrentTable';
import type { Podkop } from '../../../types';

function report(
  patch: Partial<Podkop.BitTorrentReport>,
): Podkop.BitTorrentReport {
  return {
    mode: 'bypass',
    lan: false,
    since: 7380,
    read: 2,
    counted: true,
    rows: [],
    blocked: [],
    utp_to_tcp: { packets: 0, bytes: 0 },
    ...patch,
  };
}

describe('bitTorrentTable', () => {
  it('has no card while BitTorrent goes as the other traffic', () => {
    expect(bitTorrentTable(undefined)).toBeUndefined();
    expect(bitTorrentTable(report({ mode: '' }))).toBeUndefined();
  });

  it('makes a row of each kind and way, the bytes as the dashboard shows them', () => {
    const table = bitTorrentTable(
      report({
        rows: [
          {
            kind: 'utp',
            way: 'past',
            open: 12,
            connections: 40,
            received: { packets: 1000, bytes: 1234567 },
            sent: { packets: 500, bytes: 45600 },
          },
          {
            kind: 'discovery',
            way: 'rule',
            open: 1,
            connections: 3,
            received: { packets: 2, bytes: 900 },
            sent: { packets: 2, bytes: 300 },
          },
        ],
        rule: 'Torrents',
      }),
    );
    expect(table?.mode).toBe('Past podkop');
    expect(table?.since).toBe('2 h 3 min');
    expect(table?.rows).toEqual([
      {
        kind: 'uTP',
        way: 'Past podkop',
        open: '12',
        connections: '40',
        received: '1.23 MB',
        sent: '45.6 KB',
        packets: 'Packets: received 1000, sent 500',
      },
      {
        kind: 'DHT and UDP trackers',
        way: 'Through the rule Torrents',
        open: '1',
        connections: '3',
        received: '900 B',
        sent: '300 B',
        packets: 'Packets: received 2, sent 2',
      },
    ]);
  });

  it('tells what was blocked, a failed read, a router that does not count, the module', () => {
    const table = bitTorrentTable(
      report({
        mode: 'block',
        lan: true,
        counted: false,
        error: 'no netlink',
        rows: [
          {
            kind: 'tcp',
            way: 'blocked',
            open: 1,
            connections: 1,
            received: { packets: 0, bytes: 0 },
            sent: { packets: 0, bytes: 0 },
          },
        ],
        blocked: [{ kind: 'utp', dropped: { packets: 120, bytes: 9000 } }],
        utp_to_tcp: { packets: 3, bytes: 180 },
        module: {
          learned: 50,
          replies: 4,
          announces: 1,
          watched: 6,
          confirmed: 2,
          rejected: 2,
          not_shaped: 3,
          refuted: 1,
        },
      }),
    );
    expect(table?.mode).toBe('Block · On the whole LAN');
    expect(table?.rows[0].received).toBe('—');
    expect(table?.blocked).toEqual(['uTP: 120 packets (9 KB) dropped']);
    expect(table?.notes).toEqual([
      'The last read of the connections failed: no netlink',
      'The router does not count the bytes of connections (net.netfilter.nf_conntrack_acct is 0)',
      'uTP connects turned to TCP (on a flow of the DHT): 3',
      'Peers learned: 50 from 4 replies and 1 announces',
      'Connections checked: 6; confirmed as BitTorrent: 2 (closed: 2, left open: 0); not BitTorrent: 4',
    ]);
  });

  it('says a span short', () => {
    expect(spanText(42)).toBe('42 s');
    expect(spanText(150)).toBe('2 min');
    expect(spanText(3660)).toBe('1 h 1 min');
  });
});
