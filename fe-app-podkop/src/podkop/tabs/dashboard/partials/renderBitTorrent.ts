import type {
  BitTorrentTable,
  BitTorrentTableRow,
} from '../helpers/bitTorrentTable';

// renderBitTorrent draws the card of BitTorrent of the dashboard: the mode, the kinds of its
// traffic and their ways with what was sent and received, what was blocked, the notes, and the
// button that starts the statistics again (onReset; none without it); nothing when BitTorrent goes
// as the other traffic.
//
// The rows are blocks, not a table: a row is "what" (the kind and the way) and "numbers" (sent,
// received, connections), two parts of a wrapping flex line. Wide, they sit side by side as
// columns; where the card is narrow (a phone, a theme with a side menu) the numbers of every row go
// under its "what", still under the heads of their columns. A table with nowrap cells could only
// scroll sideways, its last column out of sight, and widened the whole page in themes that give the
// tab no width of its own (the field's report of 2026-11-18); and themes style tables, each its way.
// For a screen reader it is still a table: the two parts of a row are of the layout alone.
function renderRow(row: BitTorrentTableRow, modifier: string) {
  const cell = (name: string, children: unknown[]) =>
    E('div', { class: name, role: 'cell' }, [...children]);
  return E(
    'div',
    {
      class: `pdk_dashboard-page__bittorrent__row${modifier}`,
      role: 'row',
      title: row.packets,
    },
    [
      E(
        'div',
        { class: 'pdk_dashboard-page__bittorrent__what', role: 'presentation' },
        [
          cell('pdk_dashboard-page__bittorrent__kind', [row.kind]),
          cell('pdk_dashboard-page__bittorrent__way', [row.way]),
        ],
      ),
      E(
        'div',
        {
          class: 'pdk_dashboard-page__bittorrent__numbers',
          role: 'presentation',
        },
        [
          cell('pdk_dashboard-page__bittorrent__number', [row.sent]),
          cell('pdk_dashboard-page__bittorrent__number', [row.received]),
          cell('pdk_dashboard-page__bittorrent__number', [
            row.connections,
            E('div', { class: 'pdk_dashboard-page__bittorrent__open' }, [
              _('%s open').format(row.open),
            ]),
          ]),
        ],
      ),
    ],
  );
}

function renderHead() {
  const cell = (name: string, text: string) =>
    E('div', { class: name, role: 'columnheader' }, [text]);
  return E(
    'div',
    {
      class:
        'pdk_dashboard-page__bittorrent__row pdk_dashboard-page__bittorrent__row--head',
      role: 'row',
    },
    [
      E(
        'div',
        { class: 'pdk_dashboard-page__bittorrent__what', role: 'presentation' },
        [
          cell('pdk_dashboard-page__bittorrent__kind', _('Traffic')),
          cell('pdk_dashboard-page__bittorrent__way', _('Way')),
        ],
      ),
      E(
        'div',
        {
          class: 'pdk_dashboard-page__bittorrent__numbers',
          role: 'presentation',
        },
        [
          cell('pdk_dashboard-page__bittorrent__number', _('Sent')),
          cell('pdk_dashboard-page__bittorrent__number', _('Received')),
          cell('pdk_dashboard-page__bittorrent__number', _('Connections')),
        ],
      ),
    ],
  );
}

export function renderBitTorrent(
  table: BitTorrentTable | undefined,
  onReset?: () => void,
) {
  if (!table) {
    return E('div', { class: 'pdk_dashboard-page__bittorrent hidden' }, []);
  }
  if (table.problem) {
    return E('div', { class: 'pdk_dashboard-page__bittorrent' }, [
      E('div', { class: 'pdk_dashboard-page__bittorrent__title' }, [
        E('b', {}, 'BitTorrent'),
        E('span', { class: 'pdk_dashboard-page__bittorrent__mode' }, [
          table.mode,
        ]),
      ]),
      E('div', { class: 'pdk_dashboard-page__bittorrent__blocked' }, [
        `⚠️ ${table.problem}`,
      ]),
    ]);
  }
  // the rows, as a table for a screen reader; with none, a line (not when the mode dropped
  // something: its lines below say so, and "nothing seen" over them would not be true)
  const rows = table.rows.length
    ? [
        E(
          'div',
          {
            class: 'pdk_dashboard-page__bittorrent__rows',
            role: 'table',
            'aria-label': 'BitTorrent',
          },
          [
            renderHead(),
            ...table.rows.map((row) => renderRow(row, '')),
            ...(table.total
              ? [
                  renderRow(
                    table.total,
                    ' pdk_dashboard-page__bittorrent__row--total',
                  ),
                ]
              : []),
          ],
        ),
      ]
    : table.blocked.length
      ? []
      : [
          E(
            'div',
            { class: 'pdk_dashboard-page__bittorrent__empty' },
            _('No BitTorrent traffic seen yet'),
          ),
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
    ...rows,
    ...table.blocked.map((line) =>
      E('div', { class: 'pdk_dashboard-page__bittorrent__blocked' }, [line]),
    ),
    ...table.notes.map((line) =>
      E('div', { class: 'pdk_dashboard-page__bittorrent__note' }, [line]),
    ),
    ...(table.rows.length
      ? [
          E('div', { class: 'pdk_dashboard-page__bittorrent__caption' }, [
            table.caption,
          ]),
        ]
      : []),
  ]);
}
