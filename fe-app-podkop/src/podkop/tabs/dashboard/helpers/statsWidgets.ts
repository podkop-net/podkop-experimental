import type { Podkop } from '../../../types';
import type { StoreType } from '../../../services';

type Widgets = Pick<
  StoreType,
  'bandwidthWidget' | 'trafficTotalWidget' | 'systemInfoWidget'
>;

// statsWidgets makes the widgets of the dashboard of an answer of the backend's stats and
// the one before it: the rates up and down are the bytes between the two over the time
// between them, by the backend's clock. Without the one before (the first answer, or the
// first after the page was hidden) the rates are left as they are. Counts that went down
// are those of a sing-box started since: no rate.
export function statsWidgets(
  current: Podkop.Stats | undefined,
  previous: Podkop.Stats | undefined,
): Partial<Widgets> {
  if (!current?.running) {
    return {
      bandwidthWidget: {
        loading: false,
        failed: true,
        data: { up: 0, down: 0 },
      },
      trafficTotalWidget: {
        loading: false,
        failed: true,
        data: { downloadTotal: 0, uploadTotal: 0 },
      },
      systemInfoWidget: {
        loading: false,
        failed: true,
        data: { connections: 0, memory: 0 },
      },
    };
  }
  const widgets: Partial<Widgets> = {
    trafficTotalWidget: {
      loading: false,
      failed: false,
      data: { downloadTotal: current.down, uploadTotal: current.up },
    },
    systemInfoWidget: {
      loading: false,
      failed: false,
      data: { connections: current.connections, memory: current.memory },
    },
  };
  if (previous?.running) {
    const seconds = (current.at - previous.at) / 1000;
    const rate = (now: number, before: number) =>
      seconds > 0 && now >= before ? Math.round((now - before) / seconds) : 0;
    widgets.bandwidthWidget = {
      loading: false,
      failed: false,
      data: {
        up: rate(current.up, previous.up),
        down: rate(current.down, previous.down),
      },
    };
  }
  return widgets;
}

export const SERVICES_REFRESH_MS = 10000;

// servicesStale tells whether the state of the services, read when the tab opened and after
// a button, no longer agrees with an answer of the stats: a page opened while an update or a
// restart had the backend down showed it stopped (and no grid) until it was opened again. At
// most one read every SERVICES_REFRESH_MS, so that a read that keeps failing is not repeated
// at every answer.
export function servicesStale(
  current: Podkop.Stats | undefined,
  shown: StoreType['servicesInfoWidget'],
  lastRead: number,
  now: number,
): boolean {
  if (shown.loading || now - lastRead < SERVICES_REFRESH_MS) return false;
  return Boolean(current?.running) !== Boolean(shown.data.singbox);
}
