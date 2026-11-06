import { Podkop } from '../../../types';
import { routeLabel } from '../../../methods/custom/ruleTiles';
import type { IDetectWidget } from '../../../services';
import {
  CHECK_QUEUE_LIMIT,
  batchProgress,
  canCheck,
  isChecking,
  problemServers,
  tileChip,
} from '../helpers/detectWidget';

// what the detector adds to the tiles of a section
export interface ISectionChecks {
  detect: IDetectWidget;
  onShowVerdict: (outbound: Podkop.Outbound) => void;
  onCheckServer: (outbound: Podkop.Outbound) => void;
  onCheckProblems: (section: Podkop.OutboundGroup) => void;
  onCancelChecks: () => void;
}

interface IRenderSectionsProps {
  loading: boolean;
  failed: boolean;
  section: Podkop.OutboundGroup;
  onTestLatency: (tag: string) => void;
  onChooseOutbound: (selector: string, tag: string) => void;
  latencyFetching: boolean;
  checks?: ISectionChecks;
}

function renderFailedState() {
  return E(
    'div',
    {
      class: 'pdk_dashboard-page__outbound-section centered',
      style: 'height: 127px',
    },
    E('span', {}, [E('span', {}, _('Dashboard currently unavailable'))]),
  );
}

function renderLoadingState() {
  return E('div', {
    id: 'dashboard-sections-grid-skeleton',
    class: 'pdk_dashboard-page__outbound-section skeleton',
    style: 'height: 127px',
  });
}

export function renderDefaultState({
  section,
  onChooseOutbound,
  onTestLatency,
  latencyFetching,
  checks,
}: IRenderSectionsProps) {
  function testLatency() {
    if (section.withTagSelect) {
      return onTestLatency(section.code);
    }

    if (section.outbounds.length) {
      return onTestLatency(section.outbounds[0].code);
    }
  }

  function renderOutbound(outbound: Podkop.Outbound) {
    function getLatencyClass() {
      if (!outbound.latency) {
        return 'pdk_dashboard-page__outbound-grid__item__latency--empty';
      }

      if (outbound.latency < 800) {
        return 'pdk_dashboard-page__outbound-grid__item__latency--green';
      }

      if (outbound.latency < 1500) {
        return 'pdk_dashboard-page__outbound-grid__item__latency--yellow';
      }

      return 'pdk_dashboard-page__outbound-grid__item__latency--red';
    }

    // The row of the detector: the chip opens the window of its verdict, the button asks for a
    // check. A click on a tile chooses its server, so neither lets the click through. dom.attr of
    // LuCI sets any value but null: disabled false would disable the button.
    function renderCheckRow() {
      if (!checks) return [];
      const { detect, onShowVerdict, onCheckServer } = checks;
      const chip = tileChip(outbound.code, detect);
      const checkable = canCheck(outbound, detect.noprobe);
      if (!chip && !checkable) return [];
      return [
        E(
          'div',
          {
            class: 'pdk_dashboard-page__outbound-grid__item__check',
            // a tap beside a button, or on a disabled one
            click: (event: Event) => event.stopPropagation(),
          },
          [
            ...(chip
              ? [
                  E(
                    'button',
                    {
                      class: `pdk_dashboard-page__outbound-grid__item__block pdk_dashboard-page__outbound-grid__item__block--${chip.tone}`,
                      click: (event: Event) => {
                        event.stopPropagation();
                        onShowVerdict(outbound);
                      },
                    },
                    [chip.label],
                  ),
                ]
              : []),
            ...(checkable
              ? [
                  E(
                    'button',
                    {
                      class:
                        'btn pdk_dashboard-page__outbound-grid__item__check-button',
                      disabled: isChecking(outbound.code, detect)
                        ? 'disabled'
                        : null,
                      click: (event: Event) => {
                        event.stopPropagation();
                        onCheckServer(outbound);
                      },
                    },
                    [_('Check server')],
                  ),
                ]
              : []),
          ],
        ),
      ];
    }

    // a click pins the server on the selector of the rule; direct and block as a fallback are not
    // among its choices
    const selectable = section.withTagSelect && outbound.selectable !== false;
    const classes = [
      'pdk_dashboard-page__outbound-grid__item',
      ...((outbound.active ?? outbound.selected)
        ? ['pdk_dashboard-page__outbound-grid__item--active']
        : []),
      ...(outbound.pick
        ? ['pdk_dashboard-page__outbound-grid__item--pick']
        : []),
      ...(selectable
        ? ['pdk_dashboard-page__outbound-grid__item--selectable']
        : []),
    ];
    return E(
      'div',
      {
        class: classes.join(' '),
        'data-tag': outbound.code,
        title:
          [
            outbound.pick ? _('Chosen inside the fallback') : '',
            outbound.balanced
              ? _('In the balance: %d devices').format(outbound.devices ?? 0)
              : '',
            outbound.lossTitle ?? '',
          ]
            .filter(Boolean)
            .join('\n') || null,
        click: () =>
          selectable && onChooseOutbound(section.code, outbound.code),
      },
      [
        E('b', {}, [outbound.displayName]),
        E('div', { class: 'pdk_dashboard-page__outbound-grid__item__footer' }, [
          E('div', { class: 'pdk_dashboard-page__outbound-grid__item__type' }, [
            outbound.type,
          ]),
          E('div', { class: getLatencyClass() }, [
            outbound.latency ? `${outbound.latency}ms` : 'N/A',
            ...(outbound.loss ? [` · ${outbound.loss}`] : []),
            ...(outbound.balanced ? [` · ⇄${outbound.devices ?? 0}`] : []),
          ]),
        ]),
        ...renderCheckRow(),
      ],
    );
  }

  // The check of the problem servers of a section: its button, or its progress and the way to
  // stop it. Coming back to the tab, or from another browser, the progress of a check is not known
  // here, only how many servers of this section wait for their turn.
  function renderChecks() {
    if (!checks) return [];
    const { detect, onCheckProblems, onCancelChecks } = checks;
    const queuedHere = section.outbounds.filter((outbound) =>
      detect.queued.includes(outbound.code),
    ).length;
    let progress = '';
    if (detect.batch?.section === section.code) {
      const { done, total } = batchProgress(detect);
      const found = detect.batch.found;
      progress = found
        ? _('%d of %d, first %d of %d').format(
            done,
            total,
            CHECK_QUEUE_LIMIT,
            found,
          )
        : _('%d of %d').format(done, total);
    } else if (!detect.batch && queuedHere) {
      progress = _('Queued: %d').format(queuedHere);
    }
    if (progress) {
      return [
        E(
          'span',
          {
            class: 'dashboard-sections-grid-item-check-progress',
            'aria-live': 'polite',
          },
          [progress],
        ),
        E(
          'button',
          {
            class: 'btn dashboard-sections-grid-item-check-cancel',
            click: () => onCancelChecks(),
          },
          _('Cancel'),
        ),
      ];
    }
    if (!problemServers(section, detect).length) return [];
    return [
      E(
        'button',
        {
          class: 'btn dashboard-sections-grid-item-check-problems',
          disabled: detect.batch ? 'disabled' : null,
          // the progress takes the place of the button in the section it belongs to
          title: detect.batch ? _('Another section is being checked.') : null,
          click: () => onCheckProblems(section),
        },
        _('Check problem servers'),
      ),
    ];
  }

  // How the rule chose where its connections go, and the way back from a pinned server to the
  // URL test of the rule
  function renderRoute() {
    const route = section.route;
    if (!route || route.mode === 'single') return [];
    const latency = route.latency ? `${route.latency}ms` : 'N/A';
    const auto = section.auto;
    // as the outbounds check tells it: a block in use refuses, a pin or a fallback is a warning
    let tone = '';
    if (route.code === 'block') tone = 'error';
    else if (route.mode === 'manual' || route.tier) tone = 'warning';
    return [
      E(
        'div',
        {
          class: `pdk_dashboard-page__outbound-section__route${tone ? ` pdk_dashboard-page__outbound-section__route--${tone}` : ''}`,
        },
        [
          route.balance?.length
            ? `${routeLabel(route)}: ${route.balance.join(', ')}`
            : `${routeLabel(route)}: ${route.displayName} · ${latency}`,
        ],
      ),
      ...(route.mode === 'manual' && auto
        ? [
            E(
              'button',
              {
                class: 'btn dashboard-sections-grid-item-auto',
                click: () => onChooseOutbound(section.code, auto),
              },
              _('Back to automatic choice'),
            ),
          ]
        : []),
    ];
  }

  // The tiles in the order the rule takes them. With fallbacks each tier is set apart by the tint
  // under its tiles, two in turn, and its name over its first tile; the grid stays as it is.
  function renderGrid() {
    const tiers = section.tiers ?? [];
    if (tiers.length < 2) {
      return section.outbounds.map((outbound) => renderOutbound(outbound));
    }
    return section.outbounds.map((outbound, index) => {
      const tier = outbound.tier ?? 0;
      const first = index === 0 || section.outbounds[index - 1].tier !== tier;
      return E(
        'div',
        {
          class: `pdk_dashboard-page__outbound-grid__cell pdk_dashboard-page__outbound-grid__cell--tint-${tier % 2}`,
        },
        [
          ...(first
            ? [
                E(
                  'div',
                  {
                    class: 'pdk_dashboard-page__outbound-grid__tier',
                    title: tiers[tier] ?? '',
                  },
                  [tiers[tier] ?? ''],
                ),
              ]
            : []),
          renderOutbound(outbound),
        ],
      );
    });
  }

  return E(
    'div',
    {
      class: 'pdk_dashboard-page__outbound-section',
      'data-section': section.code,
    },
    [
      // Title with test latency
      E(
        'div',
        { class: 'pdk_dashboard-page__outbound-section__title-section' },
        [
          E(
            'div',
            {
              class:
                'pdk_dashboard-page__outbound-section__title-section__title',
            },
            [section.displayName],
          ),
          ...renderRoute(),
          E(
            'div',
            {
              class:
                'pdk_dashboard-page__outbound-section__title-section__actions',
            },
            [
              ...renderChecks(),
              latencyFetching
                ? E('div', {
                    class: 'skeleton',
                    style: 'width: 99px; height: 28px',
                  })
                : E(
                    'button',
                    {
                      class: 'btn dashboard-sections-grid-item-test-latency',
                      click: () => testLatency(),
                    },
                    _('Test latency'),
                  ),
            ],
          ),
        ],
      ),
      E(
        'div',
        {
          class: `pdk_dashboard-page__outbound-grid${(section.tiers?.length ?? 0) > 1 ? ' pdk_dashboard-page__outbound-grid--tiers' : ''}`,
        },
        renderGrid(),
      ),
    ],
  );
}

export function renderSections(props: IRenderSectionsProps) {
  if (props.failed) {
    return renderFailedState();
  }

  if (props.loading) {
    return renderLoadingState();
  }

  return renderDefaultState(props);
}
