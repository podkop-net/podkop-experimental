import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  CHECK_QUEUE_LIMIT,
  batchProgress,
  canCheck,
  detectIsBusy,
  mayHang,
  oncePerControl,
  problemServers,
  problemTiles,
  settleRequested,
  tileChip,
  widgetOfReport,
} from '../helpers/detectWidget';
import type { IDetectWidget } from '../../../services';
import type { Podkop } from '../../../types';

const widget = (change: Partial<IDetectWidget> = {}): IDetectWidget => ({
  verdicts: {},
  servers: {},
  staleCures: 0,
  requested: {},
  probing: '',
  queued: [],
  noprobe: [],
  batch: null,
  ...change,
});

const report = (change: Partial<Podkop.DetectReport> = {}) => ({
  verdicts: {},
  probing: '',
  queued: [],
  noprobe: [],
  fallback: false,
  ...change,
});

const outbound = (
  code: string,
  change: Partial<Podkop.Outbound> = {},
): Podkop.Outbound => ({
  code,
  displayName: code,
  latency: 100,
  type: 'VLESS',
  selected: false,
  inUse: false,
  ...change,
});

const section = (...outbounds: Podkop.Outbound[]): Podkop.OutboundGroup => ({
  withTagSelect: true,
  code: 'main-out',
  displayName: 'main',
  outbounds,
});

describe('canCheck', () => {
  it.each(['Selector', 'URLTest', 'Direct', 'Block', 'Reject', 'DNS', ''])(
    'is not for a tile of type %j',
    (type) => {
      expect(canCheck(outbound('x', { type }), [])).toBe(false);
    },
  );

  it.each(['VLESS', 'Trojan', 'Hysteria2', 'Shadowsocks', 'Naive'])(
    'is for a server of type %s, whatever its tag says',
    (type) => {
      expect(canCheck(outbound('main-urltest-out', { type }), [])).toBe(true);
    },
  );

  it('is not for what the backend says it cannot probe', () => {
    expect(canCheck(outbound('a via b'), ['a via b'])).toBe(false);
    expect(canCheck(outbound('a via b'), ['other'])).toBe(true);
  });
});

describe('tileChip', () => {
  const limit: Podkop.Verdict = { block: 'limit', source: 'passive', kb: 18 };

  it('tells the check under way over the verdict', () => {
    const verdicts = { a: limit };
    expect(tileChip('a', widget({ verdicts }))?.label).toBe('limit?');
    expect(tileChip('a', widget({ verdicts, probing: 'a' }))?.label).toBe(
      'checking…',
    );
    expect(tileChip('a', widget({ verdicts, queued: ['a'] }))?.label).toBe(
      'queued',
    );
    expect(
      tileChip('a', widget({ verdicts, requested: { a: 1 } }))?.label,
    ).toBe('queued');
  });

  it('has none for a server with nothing to tell', () => {
    expect(tileChip('a', widget())).toBeUndefined();
  });
});

describe('problemServers', () => {
  it('takes a chip of a problem or no delay, and no working server', () => {
    const detect = widget({
      noprobe: ['tunneled'],
      verdicts: {
        limited: { block: 'limit', source: 'passive', kb: 18 },
        checked: { block: 'none', source: 'active' },
        tunneled: { block: 'limit', source: 'passive', kb: 18 },
      },
    });
    const tags = problemServers(
      section(
        outbound('fine'),
        outbound('limited'),
        outbound('silent', { latency: 0 }),
        outbound('checked', { latency: 0 }),
        outbound('tunneled'),
        outbound('group', { latency: 0, type: 'URLTest' }),
        outbound('direct', { latency: 0, type: 'Direct' }),
      ),
      detect,
    ).map(({ code }) => code);
    expect(tags).toEqual(['limited', 'silent']);
  });

  it('sends no more than the queue of the backend takes', () => {
    const many = Array.from(
      { length: CHECK_QUEUE_LIMIT + 5 },
      (_unused, index) => outbound(`s${index}`, { latency: 0 }),
    );
    expect(problemServers(section(...many), widget())).toHaveLength(
      CHECK_QUEUE_LIMIT,
    );
  });
});

describe('problemServers: what is no problem', () => {
  const take = (verdict: Podkop.Verdict, latency: number) =>
    problemServers(
      section(outbound('a', { latency })),
      widget({ verdicts: { a: verdict } }),
    ).map(({ code }) => code);

  it('leaves a refused hello of the probe out, delay or not', () => {
    const verdict: Podkop.Verdict = {
      block: 'unknown',
      source: 'active',
      notes: ['probe_hello_refused'],
    };
    expect(take(verdict, 100)).toEqual([]);
    expect(take(verdict, 0)).toEqual([]);
  });

  it.each<[Podkop.Block, Podkop.VerdictNote[]]>([
    ['unknown', ['inconclusive']],
    ['unknown', ['target_failed']],
    ['unreachable', ['uplink_down']],
    ['unreachable', ['dns_failed']],
    ['wrongparams', ['clock_suspect']],
  ])('leaves a weak %s with %j out, delay or not', (block, notes) => {
    const verdict: Podkop.Verdict = { block, source: 'active', notes };
    expect(take(verdict, 100)).toEqual([]);
    expect(take(verdict, 0)).toEqual([]);
  });

  it('leaves the notes of a working server to the delay', () => {
    for (const verdict of [
      { block: 'unknown', source: 'passive', notes: ['needs_mlkem'] },
      { block: 'unknown', source: 'passive', notes: ['fp_switched'] },
      { block: 'none', source: 'passive', notes: ['fp_switched'] },
    ] as Podkop.Verdict[]) {
      expect(take(verdict, 100)).toEqual([]);
      expect(take(verdict, 0)).toEqual(['a']);
    }
  });

  it('keeps a failed handshake beside needs_mlkem', () => {
    expect(
      take(
        {
          block: 'unknown',
          source: 'passive',
          notes: ['handshake_failed', 'needs_mlkem'],
        },
        100,
      ),
    ).toEqual(['a']);
  });

  it('keeps a failed URL test', () => {
    expect(take({ block: 'unreachable', source: 'passive' }, 100)).toEqual([
      'a',
    ]);
  });
});

describe('problemTiles', () => {
  it('puts what no probe answered first, in the order of the list', () => {
    const detect = widget({
      verdicts: {
        a: { block: 'hellodrop', source: 'active' },
        b: { block: 'hellodrop', source: 'passive' },
        c: { block: 'dead', source: 'active', n: 2 },
      },
    });
    const tags = problemTiles(
      section(
        outbound('a'),
        outbound('b'),
        outbound('c'),
        outbound('d', { latency: 0 }),
      ),
      detect,
    ).map(({ code }) => code);
    expect(tags).toEqual(['b', 'd', 'a', 'c']);
  });

  it('keeps a server silent through one relay among the problems', () => {
    const detect = widget({
      verdicts: {
        a: {
          block: 'unreachable',
          source: 'active',
          notes: ['relay_silent'],
          n: 1,
        },
      },
    });
    expect(
      problemTiles(section(outbound('a'), outbound('b')), detect).map(
        ({ code }) => code,
      ),
    ).toEqual(['a']);
  });

  it('moves on to the rest at a second press of a long list', () => {
    const many = Array.from(
      { length: CHECK_QUEUE_LIMIT + 3 },
      (_unused, index) => outbound(`s${index}`, { latency: 0 }),
    );
    const verdicts = Object.fromEntries(
      many
        .slice(0, CHECK_QUEUE_LIMIT)
        .map(({ code }) => [
          code,
          { block: 'dead', source: 'active', n: 2 } as Podkop.Verdict,
        ]),
    );
    const detect = widget({ verdicts });
    expect(problemTiles(section(...many), detect)).toHaveLength(many.length);
    expect(
      problemServers(section(...many), detect)
        .slice(0, 3)
        .map(({ code }) => code),
    ).toEqual([
      `s${CHECK_QUEUE_LIMIT}`,
      `s${CHECK_QUEUE_LIMIT + 1}`,
      `s${CHECK_QUEUE_LIMIT + 2}`,
    ]);
  });
});

describe('mayHang', () => {
  it('goes by the tags read at the press, over what the grid knows', () => {
    const stale = outbound('a', { inUse: true });
    const fresh = outbound('b');
    const used = new Set(['b']);
    expect(mayHang(stale, used)).toBe(false);
    expect(mayHang(fresh, used)).toBe(true);
  });

  it('falls back to the grid when the read failed', () => {
    expect(mayHang(outbound('a', { inUse: true }), undefined)).toBe(true);
    expect(mayHang(outbound('a'), undefined)).toBe(false);
  });

  it.each(['Hysteria', 'Hysteria2', 'TUIC'])(
    'never warns of %s, no burst goes there',
    (type) => {
      const server = outbound('a', { type, inUse: true });
      expect(mayHang(server, new Set(['a']))).toBe(false);
      expect(mayHang(server, undefined)).toBe(false);
    },
  );
});

describe('oncePerControl', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  // a read that answers when told to
  const deferred = () => {
    let answer: (value: string) => void = () => {};
    const promise = new Promise<string>((resolve) => {
      answer = resolve;
    });
    return { promise, answer };
  };

  it('ignores a press while the read of that control is pending', async () => {
    const pressed = oncePerControl();
    const { promise, answer } = deferred();
    const read = vi.fn(() => promise);
    const then = vi.fn();
    const first = pressed('a', read, then);
    await pressed('a', read, then);
    expect(read).toHaveBeenCalledTimes(1);
    expect(then).not.toHaveBeenCalled();
    answer('used');
    await first;
    expect(then).toHaveBeenCalledTimes(1);
    expect(then).toHaveBeenCalledWith('used');
  });

  it('takes a press of another control and the next one of the same', async () => {
    const pressed = oncePerControl();
    const { promise, answer } = deferred();
    const read = vi.fn(() => promise);
    const then = vi.fn();
    const first = pressed('a', read, then);
    const other = pressed('b', read, then);
    expect(read).toHaveBeenCalledTimes(2);
    answer('used');
    await Promise.all([first, other]);
    expect(then).toHaveBeenCalledTimes(2);
    await pressed('a', read, then);
    expect(read).toHaveBeenCalledTimes(3);
    expect(then).toHaveBeenCalledTimes(3);
  });

  it('goes on without the answer after 3 s, and a late one does nothing', async () => {
    vi.useFakeTimers();
    const pressed = oncePerControl();
    const { promise, answer } = deferred();
    const then = vi.fn();
    const press = pressed('a', () => promise, then);
    await vi.advanceTimersByTimeAsync(2999);
    expect(then).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1);
    await press;
    expect(then).toHaveBeenCalledTimes(1);
    expect(then).toHaveBeenCalledWith(undefined);
    answer('late');
    await vi.advanceTimersByTimeAsync(0);
    expect(then).toHaveBeenCalledTimes(1);
    // the control is free again
    await pressed('a', () => Promise.resolve('next'), then);
    expect(then).toHaveBeenLastCalledWith('next');
  });

  it('goes on without the answer when the read fails', async () => {
    const pressed = oncePerControl();
    const then = vi.fn();
    await pressed('a', () => Promise.reject(new Error('no answer')), then);
    await pressed(
      'a',
      () => {
        throw new Error('no call');
      },
      then,
    );
    expect(then).toHaveBeenCalledTimes(2);
    expect(then).toHaveBeenCalledWith(undefined);
  });
});

describe('batchProgress', () => {
  it('counts what the backend no longer has', () => {
    const batch = { section: 'main-out', tags: ['a', 'b', 'c', 'd'] };
    expect(
      batchProgress(
        widget({ batch, probing: 'b', queued: ['c'], requested: { d: 1 } }),
      ),
    ).toEqual({ done: 1, total: 4 });
  });
});

describe('settleRequested', () => {
  it('lets go of what the report tells', () => {
    expect(
      settleRequested(
        { a: 1000, b: 1000, c: 1000 },
        report({ probing: 'a', queued: ['b'] }),
        2000,
      ),
    ).toEqual({ c: 1000 });
  });

  it('lets go after the time a server may be dropped without a word', () => {
    expect(settleRequested({ a: 1000 }, report(), 30999)).toEqual({ a: 1000 });
    expect(settleRequested({ a: 1000 }, report(), 31000)).toEqual({});
  });

  it('lets go of one a probe finished since, not of an older verdict', () => {
    const now = 100000;
    const at = now - 3000;
    const verdict = (age?: number) => ({
      a: { block: 'none', source: 'active', age } as Podkop.VerdictReply,
    });
    expect(
      settleRequested({ a: at }, report({ verdicts: verdict(1) }), now),
    ).toEqual({});
    expect(
      settleRequested({ a: at }, report({ verdicts: verdict() }), now),
    ).toEqual({});
    expect(
      settleRequested({ a: at }, report({ verdicts: verdict(600) }), now),
    ).toEqual({ a: at });
  });
});

describe('widgetOfReport', () => {
  it('keeps the age and the why out of the store', () => {
    const first = widgetOfReport(
      widget(),
      report({
        verdicts: {
          a: {
            block: 'limit',
            source: 'active',
            kb: 18,
            age: 10,
            why: '3 flows cut',
          },
        },
      }),
      1000,
    );
    const second = widgetOfReport(
      widget(),
      report({
        verdicts: {
          a: {
            block: 'limit',
            source: 'active',
            kb: 18,
            age: 25,
            why: '4 flows cut',
          },
        },
      }),
      2000,
    );
    expect(first.verdicts.a).toEqual({
      block: 'limit',
      source: 'active',
      kb: 18,
    });
    expect(JSON.stringify(second)).toBe(JSON.stringify(first));
  });

  it('keeps the fallback of the report out of the store', () => {
    const next = widgetOfReport(widget(), report({ fallback: true }), 1000);
    expect(next).not.toHaveProperty('fallback');
  });

  it('keeps how many tiles a cut batch was taken from', () => {
    const batch = { section: 'main-out', tags: ['a', 'b'], found: 70 };
    expect(
      widgetOfReport(widget({ batch }), report({ queued: ['a', 'b'] }), 1000)
        .batch,
    ).toEqual(batch);
  });

  it('ends a check of a section when the backend has none of it left', () => {
    const batch = { section: 'main-out', tags: ['a', 'b'] };
    const running = widgetOfReport(
      widget({ batch }),
      report({ probing: 'a', queued: ['b'] }),
      1000,
    );
    expect(running.batch).toEqual(batch);
    const last = widgetOfReport(running, report({ probing: 'b' }), 2000);
    expect(batchProgress(last)).toEqual({ done: 1, total: 2 });
    // no verdict of a: a server dropped at its turn ends all the same
    expect(widgetOfReport(last, report(), 3000).batch).toBeNull();
  });

  it('keeps a check of a section while its servers are on their way', () => {
    const batch = { section: 'main-out', tags: ['a', 'b'] };
    const sending = widgetOfReport(
      widget({ batch, requested: { a: 1000, b: 1000 } }),
      report({ probing: 'a' }),
      2000,
    );
    expect(sending.batch).toEqual(batch);
    expect(sending.requested).toEqual({ b: 1000 });
  });
});

describe('detectIsBusy', () => {
  it('is quick only while a check is under way', () => {
    expect(detectIsBusy(widget())).toBe(false);
    expect(
      detectIsBusy(
        widget({ verdicts: { a: { block: 'none', source: 'active' } } }),
      ),
    ).toBe(false);
    expect(detectIsBusy(widget({ probing: 'a' }))).toBe(true);
    expect(detectIsBusy(widget({ queued: ['a'] }))).toBe(true);
    expect(detectIsBusy(widget({ requested: { a: 1 } }))).toBe(true);
    expect(detectIsBusy(widget({ batch: { section: 's', tags: [] } }))).toBe(
      true,
    );
  });
});
