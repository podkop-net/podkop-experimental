import { describe, expect, it } from 'vitest';
import { lossOf, routeLabel, ruleOutbounds, ruleTiles } from '../ruleTiles';

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

  it('tells the day so far as preliminary before a window has enough segments', () => {
    const loss = lossOf(
      windows([
        [1, 180, 0],
        [24, 400, 2],
      ]),
    );
    expect(loss.text).toBe('0.5%');
    expect(loss.preliminary).toBe(true);
    expect(loss.title).toContain('preliminary');
    expect(lossOf(undefined)).toEqual({
      text: undefined,
      title: undefined,
      preliminary: undefined,
    });
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

describe('ruleTiles with a choice among the fallbacks', () => {
  const tags = {
    rules: {
      main: {
        name: 'Main',
        selector: 'Main-out',
        test: 'Main-urltest-out',
        pool: 'Main-fallback-out',
      },
    },
    outbounds: {},
  };
  // the servers of the rule, its pool in the mode, and direct
  const tilesOf = (mode: string | undefined, now: string, extra = {}) =>
    ruleTiles(
      {
        'Main-out': proxy('Main-out', {
          type: 'Selector',
          now: 'Main-urltest-out',
          all: ['Main-urltest-out', 'a', 'b', 'c'],
        }),
        'Main-urltest-out': proxy('Main-urltest-out', {
          type: 'URLTest',
          now,
          all: ['a', 'Main-fallback-out', 'direct-out'],
          fallbacks: ['Main-fallback-out', 'direct-out'],
        }),
        'Main-fallback-out': proxy('Main-fallback-out', {
          type: 'URLTest',
          now: 'b',
          all: ['b', 'c'],
          mode,
          ...extra,
        }),
        a: proxy('a'),
        b: proxy('b'),
        c: proxy('c'),
        'direct-out': proxy('direct-out', { type: 'Direct' }),
      },
      'main',
      [],
      [],
      new Set(),
      tags,
    );

  it('names the tier by the choice', () => {
    expect(tilesOf(undefined, 'a').tiers).toEqual([
      'Fastest',
      'Fallback 1 · Fastest',
      'Fallback 2',
    ]);
    expect(tilesOf('loss', 'a').tiers[1]).toBe(
      'Fallback 1 · Fastest, avoiding loss',
    );
    expect(tilesOf('balance', 'a').tiers[1]).toBe('Fallback 1 · Balance');
  });

  it('shows its servers, with its choice while its turn has not come', () => {
    const { outbounds, route } = tilesOf('loss', 'a');
    expect(
      outbounds.map(({ code, tier, active, pick, selectable }) => [
        code,
        tier,
        active,
        pick,
        selectable,
      ]),
    ).toEqual([
      ['a', 0, true, false, true],
      ['b', 1, false, true, true],
      ['c', 1, false, false, true],
      ['direct-out', 2, false, false, false],
    ]);
    expect(routeLabel(route!)).toBe('Fastest');
  });

  it('tells its balance, and the devices of its servers, as the route while it is in use', () => {
    const balance = {
      balance: [
        { name: 'b', devices: 2 },
        { name: 'c', devices: 1 },
      ],
    };
    const used = tilesOf('balance', 'Main-fallback-out', balance);
    expect(used.outbounds.map((item) => item.devices)).toEqual([
      undefined,
      2,
      1,
      undefined,
    ]);
    expect(used.route).toMatchObject({
      mode: 'auto',
      tier: 1,
      balance: ['b', 'c'],
    });
    expect(routeLabel(used.route!)).toBe('Fastest → Fallback 1');
    // the servers of the rule answer: the route is theirs
    expect(tilesOf('balance', 'a', balance).route?.balance).toBeUndefined();
  });
});

describe('the tone of the loss and the tags of a rule not running', () => {
  it('reads a loss as ok, warn or error', () => {
    expect(lossOf(windows([[1, 1000, 5]])).tone).toBe('ok');
    expect(lossOf(windows([[1, 1000, 20]])).tone).toBe('warn');
    expect(lossOf(windows([[1, 1000, 60]])).tone).toBe('error');
    expect(lossOf(undefined).tone).toBeUndefined();
  });

  it('guesses no tags of a rule the backend does not run', () => {
    const tags = {
      rules: { other: { name: 'rule3', selector: 'rule3-out', test: '' } },
      outbounds: {},
    } as never;
    expect(ruleOutbounds('rule3', tags)).toEqual({ selector: '', test: '' });
    expect(ruleOutbounds('rule3')).toEqual({
      selector: 'rule3-out',
      test: 'rule3-urltest-out',
    });
  });
});
