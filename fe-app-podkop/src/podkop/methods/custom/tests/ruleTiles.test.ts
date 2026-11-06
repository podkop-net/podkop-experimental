import { describe, expect, it } from 'vitest';
import { lossOf, routeLabel, ruleTiles } from '../ruleTiles';

const proxy = (name: string, extra: Record<string, unknown> = {}) =>
  ({ name, type: 'VLESS', udp: true, history: [], ...extra }) as never;

const windows = (pairs: [number, number, number][]) => ({
  windows: pairs.map(([hours, segments, lost]) => ({
    hours,
    probes: Math.ceil(segments / 180),
    segments,
    lost,
  })),
});

describe('lossOf', () => {
  it('tells the shortest window with enough segments, as the engine weighs it', () => {
    const loss = lossOf(
      windows([
        [1, 360, 9],
        [3, 900, 18],
        [6, 1800, 18],
      ]),
    );
    expect(loss.text).toBe('2.0%');
    expect(loss.title).toContain('1h: 2.5%');
    expect(loss.title).toContain('6h: 1.0%');
  });

  it('tells nothing before a window has enough segments', () => {
    expect(lossOf(windows([[1, 180, 0]])).text).toBeUndefined();
    expect(lossOf(undefined)).toEqual({ text: undefined, title: undefined });
  });

  it('says when the last probe could not count', () => {
    expect(lossOf({ not_counted: '2026-11-06T05:00:00Z' }).title).toContain(
      'could not count',
    );
  });
});

describe('ruleTiles with the modes of the URL test', () => {
  const proxies = {
    'main-out': proxy('main-out', {
      type: 'Selector',
      now: 'main-urltest-out',
      all: ['main-urltest-out', 'a', 'b', 'c'],
    }),
    'main-urltest-out': proxy('main-urltest-out', {
      type: 'URLTest',
      now: 'a',
      all: ['a', 'b', 'c'],
      mode: 'balance',
      balance: [
        { name: 'a', devices: 2 },
        { name: 'b', devices: 1 },
      ],
    }),
    a: proxy('a', { loss: windows([[1, 800, 0]]) }),
    b: proxy('b'),
    c: proxy('c', { loss: windows([[1, 800, 40]]) }),
  };

  it('marks the servers of the balance and tells the balance as the route', () => {
    const { outbounds, route } = ruleTiles(proxies, 'main', [], [], new Set());
    expect(
      outbounds.map(({ code, balanced, devices, loss }) => [
        code,
        balanced,
        devices,
        loss,
      ]),
    ).toEqual([
      ['a', true, 2, '0.0%'],
      ['b', true, 1, undefined],
      ['c', false, undefined, '5.0%'],
    ]);
    expect(route?.choice).toBe('balance');
    expect(route?.balance).toEqual(['a', 'b']);
    expect(routeLabel(route!)).toBe('Balance');
  });

  it('names the mode loss in the route', () => {
    const lossy = {
      ...proxies,
      'main-urltest-out': proxy('main-urltest-out', {
        type: 'URLTest',
        now: 'b',
        all: ['a', 'b', 'c'],
        mode: 'loss',
      }),
    };
    const { route } = ruleTiles(lossy, 'main', [], [], new Set());
    expect(route?.choice).toBe('loss');
    expect(route?.balance).toBeUndefined();
    expect(routeLabel(route!)).toBe('Fastest, avoiding loss');
  });
});
