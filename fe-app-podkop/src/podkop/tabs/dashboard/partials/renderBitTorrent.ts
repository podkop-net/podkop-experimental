import type { BitTorrentTable } from '../helpers/bitTorrentTable';

// renderBitTorrent draws the card of BitTorrent of the dashboard: the mode, a table of the kinds of
// its traffic and their ways, what was blocked, the notes, and the button that starts the
// statistics again (onReset; none without it); nothing when BitTorrent goes as the other traffic.
export function renderBitTorrent(
  table: BitTorrentTable | undefined,
  onReset?: () => void,
) {
  if (!table) {
    return E('div', { class: 'pdk_dashboard-page__bittorrent hidden' }, []);
  }
  const head = [
    _('Traffic'),
    _('Way'),
    _('Open'),
    _('Connections'),
    _('Received'),
    _('Sent'),
  ];
  const renderedRows = table.rows.length
    ? table.rows.map((row) =>
        E('tr', { title: row.packets }, [
          E('td', {}, [row.kind]),
          E('td', {}, [row.way]),
          E('td', { class: 'number' }, [row.open]),
          E('td', { class: 'number' }, [row.connections]),
          E('td', { class: 'number' }, [row.received]),
          E('td', { class: 'number' }, [row.sent]),
        ]),
      )
    : [
        E('tr', {}, [
          E(
            'td',
            { colspan: String(head.length), class: 'empty' },
            _('No BitTorrent traffic seen yet'),
          ),
        ]),
      ];
  return E('div', { class: 'pdk_dashboard-page__bittorrent' }, [
    E('div', { class: 'pdk_dashboard-page__bittorrent__title' }, [
      E('b', {}, 'BitTorrent'),
      E('span', { class: 'pdk_dashboard-page__bittorrent__mode' }, [
        `${table.mode} · ${(table.reset ? _('%s since the reset') : _('since %s')).format(table.since)}`,
      ]),
      ...(onReset
        ? [
            E(
              'button',
              {
                class: 'btn cbi-button pdk_dashboard-page__bittorrent__reset',
                title: _('Start the statistics again from now'),
                click: onReset,
              },
              [_('Reset')],
            ),
          ]
        : []),
    ]),
    E('div', { class: 'pdk_dashboard-page__bittorrent__scroll' }, [
      E('table', { class: 'pdk_dashboard-page__bittorrent__table' }, [
        E(
          'thead',
          {},
          E(
            'tr',
            {},
            head.map((text) => E('th', {}, [text])),
          ),
        ),
        E('tbody', {}, renderedRows),
      ]),
    ]),
    ...table.blocked.map((line) =>
      E('div', { class: 'pdk_dashboard-page__bittorrent__blocked' }, [line]),
    ),
    ...table.notes.map((line) =>
      E('div', { class: 'pdk_dashboard-page__bittorrent__note' }, [line]),
    ),
  ]);
}
