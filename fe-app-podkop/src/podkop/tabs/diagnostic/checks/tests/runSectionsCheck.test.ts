import { beforeEach, describe, expect, it, vi } from 'vitest';

// the Clash API of the router, standing in
let proxies: Record<
  string,
  {
    type: string;
    now?: string;
    all?: string[];
    fallbacks?: string[];
    history?: { delay: number }[];
  }
> = {};
let groups: Record<string, Record<string, number>> = {};
let delays: Record<string, number> = {};
const groupsAsked: string[] = [];
const proxiesAsked: string[] = [];
// what a test of one outbound changes in what the URL tests have chosen
let onProxyTest = (tag: string) => void tag;
vi.mock('../../../../methods', () => ({
  PodkopShellMethods: {
    getClashApiProxies: async () => ({ success: true, data: { proxies } }),
    getClashApiGroupLatency: async (tag: string) => {
      groupsAsked.push(tag);
      return { success: true, data: groups[tag] ?? {} };
    },
    getClashApiProxyLatency: async (tag: string) => {
      proxiesAsked.push(tag);
      onProxyTest(tag);
      return delays[tag]
        ? { success: true, data: { delay: delays[tag] } }
        : { success: true, data: { delay: 0, message: 'timeout' } };
    },
  },
}));
// the rules as getDashboardSections gives them, laid out from the Clash API as it stands
let rules: string[] = [];
vi.mock('../../../../methods/custom/getDashboardSections', async () => {
  const { ruleTiles } = await import('../../../../methods/custom/ruleTiles');
  return {
    getDashboardSections: async () => ({
      success: true,
      data: rules.map((name) => ({
        withTagSelect: true,
        code: `${name}-out`,
        displayName: name,
        ...ruleTiles(proxies, name, [], [], new Set()),
      })),
    }),
  };
});
vi.mock('../../../../methods/custom/getConfigModel', () => ({
  getConfigModel: async () => ({ rules: [], sources: [], members: [] }),
}));
const stored: { state: string; items: { state: string; value: string }[] }[] =
  [];
vi.mock('../updateCheckStore', () => ({
  updateCheckStore: (check: (typeof stored)[number]) => stored.push(check),
}));

const { runSectionsCheck } = await import('../runSectionsCheck');

// the selector of a rule (the backend's plan/exits.go): its URL test and all the servers
function selector(name: string, now: string, all: string[]) {
  proxies[`${name}-out`] = { type: 'Selector', now, all };
  rules.push(name);
}

async function check() {
  stored.length = 0;
  await runSectionsCheck().catch(() => {});
  return stored[stored.length - 1];
}

const DIRECT = {
  state: 'success',
  key: 'Direct (without a proxy)',
  value: '234 ms',
};

describe('runSectionsCheck', () => {
  beforeEach(() => {
    groupsAsked.length = 0;
    proxiesAsked.length = 0;
    onProxyTest = (tag) => void tag;
    rules = [];
    proxies = {
      'msk-urltest-out': {
        type: 'URLTest',
        now: 'ru',
        all: ['ru', 'msk-fallback-1-out', 'direct-out', 'block'],
        fallbacks: ['msk-fallback-1-out', 'direct-out', 'block'],
      },
      'msk-fallback-1-out': {
        type: 'URLTest',
        now: 'de',
        all: ['de', 'us'],
      },
      ru: { type: 'VLESS' },
      de: { type: 'VLESS' },
      us: { type: 'VLESS' },
      'direct-out': { type: 'Direct' },
      block: { type: 'Reject' },
    };
    groups = { 'msk-urltest-out': { ru: 275 } };
    delays = { ru: 275, de: 150, us: 426, 'direct-out': 234 };
  });

  it('tests only the server the URL test has chosen, not the servers of the rule', async () => {
    selector('msk', 'msk-urltest-out', ['msk-urltest-out', 'ru', 'de', 'us']);
    const result = await check();
    expect(groupsAsked).toEqual([]);
    expect(proxiesAsked.sort()).toEqual(['direct-out', 'ru']);
    expect(result.state).toBe('success');
    expect(result.items).toEqual([
      { state: 'success', key: 'msk', value: 'Fastest: ru 275 ms' },
      DIRECT,
    ]);
  });

  it('tests a server several rules go through once, and direct once', async () => {
    selector('msk', 'msk-urltest-out', ['msk-urltest-out', 'ru', 'de', 'us']);
    selector('two', 'ru', ['ru']);
    proxies['msk-urltest-out'].now = 'direct-out';
    const result = await check();
    expect(proxiesAsked.sort()).toEqual(['direct-out', 'ru']);
    expect(result.items.map((item) => item.value)).toEqual([
      'Fastest → Fallback 2: Directly 234 ms',
      'ru 275 ms',
      '234 ms',
    ]);
  });

  it('tests a server pinned on the dashboard alone', async () => {
    selector('msk', 'de', ['msk-urltest-out', 'ru', 'de', 'us']);
    let result = await check();
    expect(groupsAsked).toEqual([]);
    expect(result.items[0]).toEqual({
      state: 'success',
      key: 'msk',
      value: 'Manual: de 150 ms',
    });

    delays.de = 0;
    result = await check();
    expect(result.items[0]).toEqual({
      state: 'error',
      key: 'msk',
      value: 'Manual: de — Not responding',
    });
  });

  it('names only the server of a rule of one server', async () => {
    selector('one', 'us', ['us']);
    const result = await check();
    expect(result.items[0]).toEqual({
      state: 'success',
      key: 'one',
      value: 'us 426 ms',
    });
  });

  it('tells a rule whose servers do not answer by the fallback it goes through', async () => {
    selector('msk', 'msk-urltest-out', ['msk-urltest-out', 'ru', 'de', 'us']);
    proxies['msk-urltest-out'].now = 'msk-fallback-1-out';
    let result = await check();
    expect(result.state).toBe('warning');
    expect(result.items[0]).toEqual({
      state: 'warning',
      key: 'msk',
      value: 'Fastest → Fallback 1: de 150 ms',
    });

    proxies['msk-urltest-out'].now = 'direct-out';
    result = await check();
    expect(result.items[0]).toEqual({
      state: 'warning',
      key: 'msk',
      value: 'Fastest → Fallback 2: Directly 234 ms',
    });

    proxies['msk-urltest-out'].now = 'block';
    result = await check();
    expect(result.items[0]).toEqual({
      state: 'error',
      key: 'msk',
      value: 'Fastest → Fallback 3: connections are refused',
    });
  });

  it('takes a row of the fallbacks that gave one server for a fallback', async () => {
    selector('msk', 'msk-urltest-out', ['msk-urltest-out', 'ru', 'de']);
    proxies['msk-urltest-out'] = {
      type: 'URLTest',
      now: 'de',
      all: ['ru', 'de'],
      fallbacks: ['de'],
    };
    let result = await check();
    expect(result.items[0]).toEqual({
      state: 'warning',
      key: 'msk',
      value: 'Fastest → Fallback 1: de 150 ms',
    });

    delays.de = 0;
    result = await check();
    expect(result.items[0].state).toBe('error');
  });

  it('tests the new choice alone when the chosen server fails and the URL test moves on', async () => {
    selector('msk', 'msk-urltest-out', ['msk-urltest-out', 'ru', 'de', 'us']);
    proxies['msk-urltest-out'].all = [
      'ru',
      'us',
      'msk-fallback-1-out',
      'direct-out',
      'block',
    ];
    delays.ru = 0;
    // the failure of ru stored by its test, the URL test takes us
    // sing-box chooses anew just after it answered the test
    onProxyTest = (tag) => {
      if (tag === 'ru')
        setTimeout(() => (proxies['msk-urltest-out'].now = 'us'), 100);
    };
    const result = await check();
    expect(groupsAsked).toEqual([]);
    expect(proxiesAsked.sort()).toEqual(['direct-out', 'ru', 'us']);
    expect(result.items[0]).toEqual({
      state: 'success',
      key: 'msk',
      value: 'Fastest: us 426 ms',
    });
  });

  it('takes the delay of a last test for no answer', async () => {
    // a server that holds its connections: a cut round stores no failure, the history stays
    selector('msk', 'msk-urltest-out', ['msk-urltest-out', 'ru']);
    proxies.ru.history = [{ delay: 48 }];
    delays.ru = 0;
    const result = await check();
    expect(result.items[0]).toEqual({
      state: 'error',
      key: 'msk',
      value: 'Fastest: ru — Not responding',
    });
  });

  it('fails a rule whose selector has chosen nothing it knows', async () => {
    selector('msk', 'gone', ['msk-urltest-out', 'ru']);
    const result = await check();
    expect(result.items[0]).toEqual({
      state: 'error',
      key: 'msk',
      value: 'Not responding',
    });
  });
});
