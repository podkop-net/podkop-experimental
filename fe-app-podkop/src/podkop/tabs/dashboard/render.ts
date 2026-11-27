import { renderBitTorrent, renderSections, renderWidget } from './partials';
import { sourceFilled } from '../../sources';
import { openWizard } from '../../wizard';
import type { Podkop } from '../../types';

// isSetUp tells whether a source names servers: the condition the backend runs by (a router
// with no filled source is left alone)
export function isSetUp(): boolean {
  return (uci.sections('podkop', 'source') as Podkop.ConfigSource[]).some(
    (item) => sourceFilled(item),
  );
}

// the dashboard of a router that is not set up yet: what it is, and the way to set it up
function renderEmpty() {
  return E('div', { id: 'dashboard-empty', class: 'pdk-dashboard-empty' }, [
    E('div', { class: 'pdk-dashboard-empty__title' }, [
      'Podkop ещё не настроен',
    ]),
    E('div', { class: 'pdk-dashboard-empty__text' }, [
      'Роутер работает как обычно: podkop ничего не меняет, пока вы его не настроите. Понадобится ссылка на подписку или на сервер — от провайдера или своя.',
    ]),
    E(
      'button',
      {
        class: 'btn cbi-button cbi-button-action important',
        click: (event: Event) => {
          event.preventDefault();
          openWizard();
        },
      },
      ['Начать настройку'],
    ),
  ]);
}

export function render() {
  if (!isSetUp()) return renderEmpty();
  return E(
    'div',
    {
      id: 'dashboard-status',
      class: 'pdk_dashboard-page',
    },
    [
      // Widgets section
      E('div', { class: 'pdk_dashboard-page__widgets-section' }, [
        E(
          'div',
          { id: 'dashboard-widget-traffic' },
          renderWidget({ loading: true, failed: false, title: '', items: [] }),
        ),
        E(
          'div',
          { id: 'dashboard-widget-traffic-total' },
          renderWidget({ loading: true, failed: false, title: '', items: [] }),
        ),
        E(
          'div',
          { id: 'dashboard-widget-system-info' },
          renderWidget({ loading: true, failed: false, title: '', items: [] }),
        ),
        E(
          'div',
          { id: 'dashboard-widget-service-info' },
          renderWidget({ loading: true, failed: false, title: '', items: [] }),
        ),
      ]),
      // BitTorrent, while it does not go as the other traffic
      E('div', { id: 'dashboard-bittorrent' }, renderBitTorrent(undefined)),
      // All outbounds
      E(
        'div',
        { id: 'dashboard-sections-grid' },
        renderSections({
          loading: true,
          failed: false,
          section: {
            code: '',
            displayName: '',
            outbounds: [],
            withTagSelect: false,
          },
          onTestLatency: () => {},
          onChooseOutbound: () => {},
          latencyFetching: false,
        }),
      ),
    ],
  );
}
