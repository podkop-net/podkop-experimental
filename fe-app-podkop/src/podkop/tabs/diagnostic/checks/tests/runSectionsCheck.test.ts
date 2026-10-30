import { beforeEach, describe, expect, it, vi } from 'vitest';

// the Clash API of the router, standing in
let proxies: Record<string, { type: string; now?: string }> = {};
let groups: Record<string, Record<string, number>> = {};
let delays: Record<string, number> = {};
const groupsAsked: string[] = [];
vi.mock('../../../../methods', () => ({
  PodkopShellMethods: {
    getClashApiProxies: async () => ({ success: true, data: { proxies } }),
    getClashApiGroupLatency: async (tag: string) => {
      groupsAsked.push(tag);
      return { success: true, data: groups[tag] ?? {} };
    },
    getClashApiProxyLatency: async (tag: string) =>
      delays[tag]
        ? { success: true, data: { delay: delays[tag] } }
        : { success: true, data: { delay: 0, message: 'timeout' } },
  },
}));
let sections: unknown[] = [];
vi.mock('../../../../methods/custom/getDashboardSections', () => ({
  getDashboardSections: async () => ({ success: true, data: sections }),
}));
const stored: { state: string; items: { state: string; value: string }[] }[] =
  [];
vi.mock('../updateCheckStore', () => ({
  updateCheckStore: (check: (typeof stored)[number]) => stored.push(check),
}));

const { runSectionsCheck } = await import('../runSectionsCheck');

// a rule as getDashboardSections gives it: its selector offers the URL test, the servers and
// the tiers of the fallbacks of several servers
function rule(name: string, selected: string, offered: string[]) {
  return {
    withTagSelect: true,
    code: `${name}-out`,
    displayName: name,
    outbounds: offered.map((code) => ({
      code,
      displayName: code.endsWith('-urltest-out')
        ? 'Fastest'
        : code.replace(/^.+-fallback-(\d+)-out$/, 'Fallback $1'),
      latency: 0,
      type: proxies[code]?.type ?? '',
      selected: code === selected,
    })),
  };
}

async function check() {
  stored.length = 0;
  await runSectionsCheck().catch(() => {});
  return stored[stored.length - 1];
}

describe('runSectionsCheck', () => {
  beforeEach(() => {
    groupsAsked.length = 0;
    proxies = {
      'msk-urltest-out': { type: 'URLTest', now: 'ru' },
      'msk-fallback-1-out': { type: 'URLTest', now: 'de' },
      ru: { type: 'VLESS' },
      de: { type: 'VLESS' },
      us: { type: 'VLESS' },
      'direct-out': { type: 'Direct' },
    };
    groups = {
      'msk-urltest-out': { ru: 275 },
      'msk-fallback-1-out': { ru: 272, de: 142, us: 426 },
    };
    delays = { ru: 275, de: 150, 'msk-fallback-1-out': 150, 'direct-out': 234 };
  });

  it('tests the servers of the rule, not those of its fallbacks', async () => {
    sections = [
      rule('msk', 'msk-urltest-out', [
        'msk-urltest-out',
        'ru',
        'msk-fallback-1-out',
      ]),
    ];
    const result = await check();
    expect(groupsAsked).toEqual(['msk-urltest-out']);
    expect(result.state).toBe('success');
    expect(result.items).toEqual([
      { state: 'success', key: 'msk', value: '[Fastest] 275ms' },
      { state: 'success', key: 'Direct (without a proxy)', value: '234 ms' },
    ]);
  });

  it('tests a server or a tier pinned on the dashboard alone', async () => {
    sections = [
      rule('msk', 'de', ['msk-urltest-out', 'ru', 'de']),
      rule('tier', 'msk-fallback-1-out', [
        'msk-urltest-out',
        'ru',
        'msk-fallback-1-out',
      ]),
    ];
    const result = await check();
    expect(groupsAsked).toEqual(['msk-fallback-1-out']);
    expect(result.items.slice(0, 2)).toEqual([
      { state: 'success', key: 'msk', value: '[de] 150ms' },
      {
        state: 'success',
        key: 'tier',
        value: '[Fallback 1] 142ms / 272ms / 426ms',
      },
    ]);
  });

  it('tells a rule whose servers do not answer by the fallback it goes through', async () => {
    groups['msk-urltest-out'] = {};
    proxies['msk-urltest-out'].now = 'msk-fallback-1-out';
    sections = [
      rule('msk', 'msk-urltest-out', [
        'msk-urltest-out',
        'ru',
        'msk-fallback-1-out',
      ]),
    ];
    let result = await check();
    expect(result.state).toBe('warning');
    expect(result.items[0]).toEqual({
      state: 'warning',
      key: 'msk',
      value: '[Fastest → Fallback 1] 150ms',
    });

    proxies['msk-urltest-out'].now = 'direct-out';
    result = await check();
    expect(result.items[0].value).toBe('[Fastest → Directly] 234ms');

    proxies['msk-urltest-out'].now = 'block';
    result = await check();
    expect(result.items[0]).toEqual({
      state: 'error',
      key: 'msk',
      value: '[Fastest] Not responding',
    });
  });

  it('takes no delays during a round of the URL test for a failure', async () => {
    groups['msk-urltest-out'] = {};
    sections = [rule('msk', 'msk-urltest-out', ['msk-urltest-out', 'ru'])];
    const result = await check();
    expect(result.items[0]).toEqual({
      state: 'success',
      key: 'msk',
      value: '[Fastest → ru] 275ms',
    });
  });
});
