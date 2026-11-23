import { describe, expect, it, vi } from 'vitest';
import type { ApplyRecord, LuciChanges } from '../applyBar';
import type { Podkop } from '../types';

// the logic of the bar only: the router and the page's services are not asked
vi.mock('../methods', () => ({ PodkopShellMethods: {} }));
vi.mock('../services', () => ({ logger: { warn: () => {} } }));
vi.mock('../../helpers', () => ({ withTimeout: (p: Promise<unknown>) => p }));

const {
  barView,
  clockOf,
  countChanges,
  APPLY_DEADLINE_MS,
  judge,
  newRecord,
  parseRecord,
  tellsResult,
  wrapApply,
} = await import('../applyBar');

const T0 = 1795000000000;
const BEFORE = '2026-11-23T09:03:04.123Z';
const AFTER = '2026-11-23T09:03:05.200Z';

function status(fields: Partial<Podkop.GetStatus>): Podkop.GetStatus {
  return { enabled: 1, status: 'enabled', ...fields };
}

const running = status({
  backend: true,
  running: true,
  since: BEFORE,
  last: { ok: true, message: 'started in 200 ms' },
  last_at: BEFORE,
});

describe('countChanges', () => {
  it("counts podkop's change records apart from the others", () => {
    expect(
      countChanges({
        podkop: [
          ['set', 'main', 'label', 'x'],
          ['remove', 'src2'],
        ],
        network: [['set', 'lan', 'ipaddr', '192.168.2.1']],
        firewall: [],
      }),
    ).toEqual({ podkop: 2, other: 1 });
  });

  it('takes nothing for no answer', () => {
    expect(countChanges(undefined)).toEqual({ podkop: 0, other: 0 });
    expect(countChanges({})).toEqual({ podkop: 0, other: 0 });
    expect(countChanges({ podkop: 'x' })).toEqual({ podkop: 0, other: 0 });
  });
});

describe('tellsResult and newRecord', () => {
  it('tells the backend of 0.8.22 from that of 0.8.21', () => {
    expect(tellsResult(running)).toBe(true);
    expect(tellsResult(status({ backend: false, running: false }))).toBe(true);
    expect(tellsResult({ enabled: 1, status: 'enabled' })).toBe(false);
    expect(tellsResult(null)).toBe(false);
    expect(tellsResult('{"enabled":1}')).toBe(false);
  });

  it('waits for a result after the one read before the apply', () => {
    expect(newRecord(running, null, T0)).toEqual({
      started: T0,
      base: BEFORE,
      backend: true,
    });
  });

  it("takes the page's first read when the one before the apply failed", () => {
    expect(newRecord(null, running, T0)?.base).toBe(BEFORE);
  });

  it('has no base when the backend has no result yet, or does not run', () => {
    expect(
      newRecord(status({ backend: true, running: false }), null, T0),
    ).toEqual({
      started: T0,
      base: null,
      backend: true,
    });
    expect(
      newRecord(status({ backend: false, running: false }), running, T0),
    ).toEqual({
      started: T0,
      base: null,
      backend: false,
    });
  });

  it('waits for nothing with a backend of 0.8.21 or no answer', () => {
    expect(newRecord({ enabled: 1, status: 'enabled' }, null, T0)).toBeNull();
    expect(newRecord(null, null, T0)).toBeNull();
  });
});

describe('judge', () => {
  const record: ApplyRecord = { started: T0, base: BEFORE, backend: true };

  it('waits while the result is the one before the apply', () => {
    expect(judge(record, running, T0 + 7000)).toBeUndefined();
  });

  it('waits while nothing answers, until the deadline', () => {
    expect(judge(record, null, T0 + APPLY_DEADLINE_MS - 1)).toBeUndefined();
    expect(judge(record, null, T0 + APPLY_DEADLINE_MS)).toEqual({
      kind: 'unknown',
    });
  });

  it('takes a new result, applied or refused', () => {
    const applied = status({
      ...running,
      last: {
        ok: true,
        message: 'applied in 50 ms, sing-box runs the new configuration',
      },
      last_at: AFTER,
    });
    expect(judge(record, applied, T0 + 7000)).toEqual({
      kind: 'applied',
      at: AFTER,
      message: 'applied in 50 ms, sing-box runs the new configuration',
    });
    const refused = status({
      ...running,
      last: {
        ok: false,
        message:
          'the settings cannot be used, nothing is changed: rules main and second: the mixed proxies have the same port 2080',
      },
      last_at: AFTER,
    });
    expect(judge(record, refused, T0 + 7000)?.kind).toBe('refused');
  });

  it("compares the backend's times with each other only: a browser clock off by hours changes nothing", () => {
    const later = status({ ...running, last_at: AFTER });
    expect(
      judge(
        { ...record, started: T0 + 5 * 3600 * 1000 },
        later,
        T0 + 5 * 3600 * 1000 + 3000,
      )?.kind,
    ).toBe('applied');
  });

  it('takes the first result of a backend that had none', () => {
    const fresh: ApplyRecord = { started: T0, base: null, backend: true };
    expect(
      judge(fresh, status({ backend: true, running: false }), T0 + 1000),
    ).toBeUndefined();
    expect(judge(fresh, running, T0 + 2000)?.kind).toBe('applied');
  });

  it('tells at once that a backend that did not run before does not run now', () => {
    const stopped: ApplyRecord = { started: T0, base: null, backend: false };
    expect(
      judge(stopped, status({ backend: false, running: false }), T0 + 6000),
    ).toEqual({
      kind: 'stopped',
    });
  });

  it('waits for a backend that ran before and is gone (procd starts it again), until the deadline', () => {
    const gone = status({ backend: false, running: false });
    expect(judge(record, gone, T0 + 6000)).toBeUndefined();
    expect(judge(record, gone, T0 + APPLY_DEADLINE_MS)).toEqual({
      kind: 'stopped',
    });
  });
});

describe('parseRecord', () => {
  const record: ApplyRecord = { started: T0, base: BEFORE, backend: true };

  it('reads a record of this visit', () => {
    expect(parseRecord(JSON.stringify(record), T0 + 9000)).toEqual(record);
    const done = {
      ...record,
      result: { kind: 'applied', at: AFTER, message: 'm' },
    };
    expect(parseRecord(JSON.stringify(done), T0 + 9000)).toEqual(done);
  });

  it('drops one of another visit, or one that is not a record', () => {
    expect(parseRecord(JSON.stringify(record), T0 + 10 * 60 * 1000)).toBeNull();
    expect(parseRecord(null, T0)).toBeNull();
    expect(parseRecord('{', T0)).toBeNull();
    expect(
      parseRecord(
        JSON.stringify({ started: 'x', base: null, backend: true }),
        T0,
      ),
    ).toBeNull();
    expect(
      parseRecord(JSON.stringify({ started: T0, base: 5, backend: true }), T0),
    ).toBeNull();
  });
});

describe('clockOf', () => {
  it("is HH:MM of the browser's zone", () => {
    const local = new Date(2026, 10, 23, 7, 5, 59);
    expect(clockOf(local.toISOString())).toBe('07:05');
  });

  it('keeps a time it cannot read', () => {
    expect(clockOf('soon')).toBe('soon');
    expect(clockOf(undefined)).toBe('');
  });
});

describe('barView', () => {
  const none = { podkop: 0, other: 0 };

  it('shows nothing without changes or a result', () => {
    expect(barView({ changes: none, waiting: false }).kind).toBe('none');
    expect(
      barView({ changes: { podkop: 0, other: 4 }, waiting: false }).kind,
    ).toBe('none');
  });

  it("counts podkop's changes, and says when the buttons take other pages' changes too", () => {
    expect(
      barView({ changes: { podkop: 1, other: 0 }, waiting: false }),
    ).toEqual({
      kind: 'pending',
      text: 'Changes saved but not applied: 1',
      buttons: ['apply', 'show', 'revert'],
    });
    expect(
      barView({ changes: { podkop: 3, other: 2 }, waiting: false }).text,
    ).toBe(
      'Changes saved but not applied: 3 (and 2 on other pages: the buttons take them too)',
    );
  });

  it('shows the wait before anything else', () => {
    expect(
      barView({
        changes: { podkop: 2, other: 0 },
        waiting: true,
        result: { kind: 'unknown' },
      }),
    ).toEqual({ kind: 'waiting', text: 'Applying the settings…', buttons: [] });
  });

  it("shows the result with the backend's message, unless new changes wait", () => {
    const at = new Date(2026, 10, 23, 12, 3).toISOString();
    const applied = {
      kind: 'applied' as const,
      at,
      message: 'applied in 50 ms, sing-box runs the new configuration',
    };
    expect(barView({ changes: none, waiting: false, result: applied })).toEqual(
      {
        kind: 'applied',
        text: 'Applied 12:03: applied in 50 ms, sing-box runs the new configuration',
        buttons: ['dismiss'],
      },
    );
    expect(
      barView({
        changes: { podkop: 1, other: 0 },
        waiting: false,
        result: applied,
      }).kind,
    ).toBe('pending');
    const refused = {
      kind: 'refused' as const,
      at,
      message: 'the settings cannot be used, nothing is changed: x',
    };
    expect(
      barView({ changes: none, waiting: false, result: refused }).text,
    ).toBe(
      'Not applied 12:03: the settings cannot be used, nothing is changed: x',
    );
  });

  it('says when it cannot tell, and when podkop does not run', () => {
    expect(
      barView({ changes: none, waiting: false, result: { kind: 'unknown' } })
        .text,
    ).toBe(
      `podkop did not tell within ${APPLY_DEADLINE_MS / 1000} s whether it applied the settings: see Diagnostics → View logs`,
    );
    expect(
      barView({ changes: none, waiting: false, result: { kind: 'stopped' } })
        .kind,
    ).toBe('stopped');
  });
});

describe('wrapApply', () => {
  function changes() {
    const calls: Array<{ self: unknown; checked: unknown }> = [];
    const target: LuciChanges = {
      apply(this: unknown, checked?: boolean) {
        calls.push({ self: this, checked });
      },
      revert: () => undefined,
      displayChanges: () => undefined,
      renderChangeIndicator: () => undefined,
    };
    return { target, calls };
  }

  it("runs LuCI's apply after the reads, with its argument and its object", async () => {
    const { target, calls } = changes();
    const before = vi.fn(() => Promise.resolve());
    wrapApply(target, before);
    target.apply(true);
    expect(before).toHaveBeenCalledOnce();
    expect(calls).toEqual([]);
    await vi.waitFor(() => expect(calls).toHaveLength(1));
    expect(calls[0]).toEqual({ self: target, checked: true });
  });

  it('applies whatever the reads came to', async () => {
    const { target, calls } = changes();
    wrapApply(target, () => Promise.reject(new Error('no answer')));
    target.apply(false);
    await vi.waitFor(() => expect(calls).toHaveLength(1));
    const thrower = changes();
    wrapApply(thrower.target, () => {
      throw new Error('broken');
    });
    thrower.target.apply(true);
    await vi.waitFor(() => expect(thrower.calls).toHaveLength(1));
  });

  it('takes one apply at a time, and wraps once', async () => {
    const { target, calls } = changes();
    let release: () => void = () => undefined;
    const before = vi.fn(
      () => new Promise<void>((resolve) => (release = resolve)),
    );
    wrapApply(target, before);
    wrapApply(target, before);
    target.apply(true);
    target.apply(true);
    expect(before).toHaveBeenCalledOnce();
    release();
    await vi.waitFor(() => expect(calls).toHaveLength(1));
    target.apply(true);
    expect(before).toHaveBeenCalledTimes(2);
  });

  it('is called unbound as LuCI binds it, on the object it wraps', async () => {
    const { target, calls } = changes();
    wrapApply(target, () => Promise.resolve());
    const bound = target.apply;
    bound(false);
    await vi.waitFor(() => expect(calls).toHaveLength(1));
    expect(calls[0].self).toBe(target);
  });
});
