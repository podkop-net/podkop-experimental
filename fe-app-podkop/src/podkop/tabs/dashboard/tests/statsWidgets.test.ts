import { describe, expect, it } from 'vitest';
import {
  SERVICES_REFRESH_MS,
  servicesStale,
  statsWidgets,
} from '../helpers/statsWidgets';
import type { Podkop } from '../../../types';

function stats(patch: Partial<Podkop.Stats>): Podkop.Stats {
  return {
    running: true,
    at: 0,
    up: 0,
    down: 0,
    connections: 0,
    memory: 0,
    ...patch,
  };
}

describe('statsWidgets', () => {
  it('makes the rates of two answers by the clock of the backend', () => {
    const widgets = statsWidgets(
      stats({ at: 3000, up: 3000, down: 9000, connections: 4, memory: 7 }),
      stats({ at: 1000, up: 1000, down: 1000 }),
    );
    expect(widgets.bandwidthWidget?.data).toEqual({ up: 1000, down: 4000 });
    expect(widgets.trafficTotalWidget?.data).toEqual({
      downloadTotal: 9000,
      uploadTotal: 3000,
    });
    expect(widgets.systemInfoWidget?.data).toEqual({
      connections: 4,
      memory: 7,
    });
  });

  it('leaves the rates for the first answer', () => {
    const widgets = statsWidgets(stats({ up: 5 }), undefined);
    expect(widgets.bandwidthWidget).toBeUndefined();
    expect(widgets.trafficTotalWidget?.failed).toBe(false);
  });

  it('gives no rate when the counts went down (another sing-box)', () => {
    const widgets = statsWidgets(
      stats({ at: 2000, up: 10, down: 10 }),
      stats({ at: 1000, up: 500, down: 500 }),
    );
    expect(widgets.bandwidthWidget?.data).toEqual({ up: 0, down: 0 });
  });

  it('fails every widget when nothing runs', () => {
    for (const current of [undefined, stats({ running: false })]) {
      const widgets = statsWidgets(current, stats({}));
      expect(widgets.bandwidthWidget?.failed).toBe(true);
      expect(widgets.trafficTotalWidget?.failed).toBe(true);
      expect(widgets.systemInfoWidget?.failed).toBe(true);
    }
  });
});

describe('servicesStale', () => {
  const shown = (singbox: number, loading = false) => ({
    loading,
    failed: false,
    data: { singbox, podkop: 1 },
  });
  const later = SERVICES_REFRESH_MS + 1;

  it('reads the services again when the backend came up after the tab opened', () => {
    expect(servicesStale(stats({}), shown(0), 0, later)).toBe(true);
  });

  it('reads them again when the backend went away', () => {
    for (const current of [undefined, stats({ running: false })]) {
      expect(servicesStale(current, shown(1), 0, later)).toBe(true);
    }
  });

  it('leaves them while they agree, while a read goes on, and soon after a read', () => {
    expect(servicesStale(stats({}), shown(1), 0, later)).toBe(false);
    expect(servicesStale(undefined, shown(0), 0, later)).toBe(false);
    expect(servicesStale(stats({}), shown(0, true), 0, later)).toBe(false);
    expect(servicesStale(stats({}), shown(0), 5000, 5000 + later - 2)).toBe(
      false,
    );
  });
});
