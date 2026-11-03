import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  getDashboardSections,
  getUsedTags,
  usedTags,
} from '../getDashboardSections';
import { getConfigModel } from '../getConfigModel';
import { PodkopShellMethods } from '../../shell';

vi.mock('../getConfigModel', () => ({ getConfigModel: vi.fn() }));
vi.mock('../../shell', () => ({
  PodkopShellMethods: { getClashApiProxies: vi.fn() },
}));

const proxy = (name, extra = {}) => ({ name, history: [], ...extra });

const SUB = {
  '.name': 'src1',
  type: 'subscription',
  url: 'https://sub.example.org/api/sub/x',
};
const WARP = {
  '.name': 'src3',
  type: 'interface',
  interface: 'awg0',
  label: 'WARP',
};
const ONE = {
  '.name': 'src2',
  type: 'links',
  link: ['hy2://secret@198.51.100.9:443#Hetzner'],
};

function mockModel(model) {
  getConfigModel.mockResolvedValue({
    rules: [],
    sources: [],
    members: [],
    ...model,
  });
}

function mockProxies(proxies) {
  PodkopShellMethods.getClashApiProxies.mockResolvedValue({
    success: true,
    data: { proxies },
  });
}

describe('getDashboardSections', () => {
  beforeEach(() => vi.clearAllMocks());

  it('tells the server the connections go through, directly or by the URL test', async () => {
    mockModel({
      rules: [{ '.name': 'main' }],
      sources: [ONE],
      members: [{ section: 'main', role: 'server', source: 'src2' }],
    });
    mockProxies({
      'main-out': proxy('main-out', {
        type: 'Selector',
        now: 'main-urltest-out',
        all: ['main-urltest-out', 'src2', 'src4'],
      }),
      'main-urltest-out': proxy('main-urltest-out', {
        type: 'URLTest',
        now: 'src2',
      }),
      src2: proxy('src2', { type: 'Hysteria2' }),
      src4: proxy('src4', { type: 'VLESS' }),
    });
    const { data } = await getDashboardSections();
    expect(
      data[0].outbounds.map(({ code, selected, inUse, active }) => [
        code,
        selected,
        inUse,
        active,
      ]),
    ).toEqual([
      ['src2', false, true, true],
      ['src4', false, false, false],
    ]);
    expect(data[0].auto).toBe('main-urltest-out');
    expect(data[0].tiers).toEqual([]);
    expect(data[0].route).toEqual({
      mode: 'auto',
      tier: 0,
      code: 'src2',
      displayName: 'Hetzner',
      latency: 0,
    });
  });

  it('tells a server another rule goes through as in use', async () => {
    mockModel({
      rules: [{ '.name': 'one' }, { '.name': 'two' }],
      sources: [ONE],
      members: [
        { section: 'one', role: 'server', source: 'src2' },
        { section: 'two', role: 'server', source: 'src2' },
      ],
    });
    mockProxies({
      'one-out': proxy('one-out', {
        type: 'Selector',
        now: 'one-urltest-out',
        all: ['one-urltest-out', 'x', 'y'],
      }),
      'one-urltest-out': proxy('one-urltest-out', {
        type: 'URLTest',
        now: 'x',
      }),
      'two-out': proxy('two-out', {
        type: 'Selector',
        now: 'two-urltest-out',
        all: ['two-urltest-out', 'x', 'y', 'z'],
      }),
      'two-urltest-out': proxy('two-urltest-out', {
        type: 'URLTest',
        now: 'y',
      }),
      x: proxy('x', { type: 'VLESS' }),
      y: proxy('y', { type: 'VLESS' }),
      z: proxy('z', { type: 'VLESS' }),
    });
    const { data } = await getDashboardSections();
    const used = (section) =>
      section.outbounds.filter(({ inUse }) => inUse).map(({ code }) => code);
    expect(used(data[0])).toEqual(['x', 'y']);
    expect(used(data[1])).toEqual(['x', 'y']);
    // what this rule goes through is its own
    const active = (section) =>
      section.outbounds.filter(({ active }) => active).map(({ code }) => code);
    expect(active(data[0])).toEqual(['x']);
    expect(active(data[1])).toEqual(['y']);
  });

  it('walks what is in use to the end, through the URL test of a fallback', () => {
    const proxies = {
      'a-out': proxy('a-out', { now: 'a-urltest-out' }),
      'a-urltest-out': proxy('a-urltest-out', { now: 'a-fallback-1-out' }),
      'a-fallback-1-out': proxy('a-fallback-1-out', { now: 'x' }),
      x: proxy('x', { type: 'VLESS' }),
    };
    expect(usedTags(proxies, ['a-out'])).toEqual(
      new Set(['a-urltest-out', 'a-fallback-1-out', 'x']),
    );
  });

  it('walks past a tag another selector has already walked', () => {
    const proxies = {
      'a-out': proxy('a-out', { now: 'shared' }),
      'b-out': proxy('b-out', { now: 'y' }),
      'c-out': proxy('c-out', { now: 'shared' }),
      shared: proxy('shared', { now: 'x' }),
    };
    expect(usedTags(proxies, ['a-out', 'b-out', 'c-out'])).toEqual(
      new Set(['shared', 'x', 'y']),
    );
  });

  it('stops at a loop of choices', () => {
    const proxies = {
      'a-out': proxy('a-out', { now: 'g1' }),
      g1: proxy('g1', { now: 'g2' }),
      g2: proxy('g2', { now: 'g1' }),
    };
    expect(usedTags(proxies, ['a-out'])).toEqual(new Set(['g1', 'g2']));
  });

  it('reads what is in use anew, and says when it cannot', async () => {
    mockProxies({
      'main-out': proxy('main-out', { now: 'main-urltest-out' }),
      'main-urltest-out': proxy('main-urltest-out', { now: 'x' }),
      'gone-out': proxy('gone-out', {}),
    });
    expect(await getUsedTags(['main-out', 'gone-out', 'absent-out'])).toEqual(
      new Set(['main-urltest-out', 'x']),
    );
    PodkopShellMethods.getClashApiProxies.mockResolvedValue({
      success: false,
      error: '',
    });
    expect(await getUsedTags(['main-out'])).toBeUndefined();
    PodkopShellMethods.getClashApiProxies.mockResolvedValue({
      success: true,
      data: 'not an answer',
    });
    expect(await getUsedTags(['main-out'])).toBeUndefined();
  });

  it('shows the one server of a rule that has no test', async () => {
    mockModel({
      rules: [{ '.name': 'main' }],
      sources: [ONE],
      members: [{ section: 'main', role: 'server', source: 'src2' }],
    });
    mockProxies({
      'main-out': proxy('main-out', {
        type: 'Selector',
        now: 'src2',
        all: ['src2'],
      }),
      src2: proxy('src2', { type: 'Hysteria2' }),
    });
    const { data } = await getDashboardSections();
    expect(data[0].outbounds).toHaveLength(1);
    expect(data[0].outbounds[0]).toMatchObject({
      code: 'src2',
      selected: true,
      type: 'Hysteria2',
    });
    expect(data[0].outbounds[0].displayName).not.toBe('Fastest');
    expect(data[0].tiers).toEqual([]);
    expect(data[0].route?.mode).toBe('single');
  });

  it('lays out the servers of a rule by the labels of their sources, then each fallback in its turn', async () => {
    mockModel({
      rules: [{ '.name': 'main', label: 'Main' }],
      sources: [SUB, ONE, WARP],
      members: [
        { section: 'main', role: 'server', source: 'src1', via: 'src3' },
        { section: 'main', role: 'server', source: 'src2' },
        { section: 'main', role: 'fallback', source: 'src9' },
        { section: 'main', role: 'fallback', source: 'src1' },
        { section: 'main', role: 'fallback', source: 'direct' },
        { section: 'main', role: 'fallback', source: 'block' },
      ],
    });
    mockProxies({
      'main-out': proxy('main-out', {
        type: 'Selector',
        now: 'main-urltest-out',
        all: [
          'main-urltest-out',
          'src1: NL 1 via src3',
          'src2',
          'src4',
          'src1: DE 1',
          'src1: FI 1',
        ],
      }),
      'main-urltest-out': proxy('main-urltest-out', {
        type: 'URLTest',
        now: 'main-fallback-2-out',
        all: [
          'src1: NL 1 via src3',
          'src2',
          'main-fallback-2-out',
          'direct-out',
          'block',
        ],
        fallbacks: ['main-fallback-2-out', 'direct-out', 'block'],
      }),
      'src1: NL 1 via src3': proxy('src1: NL 1 via src3', {
        type: 'VLESS',
        history: [{ delay: 120 }],
      }),
      src2: proxy('src2', { type: 'Hysteria2' }),
      src4: proxy('src4', { type: 'VLESS' }),
      'main-fallback-2-out': proxy('main-fallback-2-out', {
        type: 'URLTest',
        now: 'src1: FI 1',
        all: ['src1: DE 1', 'src1: FI 1'],
      }),
      'src1: DE 1': proxy('src1: DE 1', { type: 'VLESS' }),
      'src1: FI 1': proxy('src1: FI 1', {
        type: 'VLESS',
        history: [{ delay: 210 }],
      }),
      'direct-out': proxy('direct-out', { type: 'Direct' }),
      block: proxy('block', { type: 'Reject' }),
    });

    const result = await getDashboardSections();
    expect(result.success).toBe(true);
    const [rule] = result.data;
    expect(rule.withTagSelect).toBe(true);
    expect(rule.code).toBe('main-out');
    expect(rule.displayName).toBe('Main');
    // the first fallback row took no server: the tier of the second is the first fallback, and
    // its name comes from its own row
    expect(rule.tiers).toEqual([
      'Fastest',
      'Fallback 1 · sub.example.org',
      'Fallback 2',
      'Fallback 3',
    ]);
    expect(
      rule.outbounds.map((item) => [
        item.displayName,
        item.tier,
        item.selectable,
        item.active,
        item.pick,
      ]),
    ).toEqual([
      ['sub.example.org: NL 1 via WARP', 0, true, false, false],
      ['Hetzner', 0, true, false, false],
      // offered by the selector beyond the URL test: in view with the servers
      ['src4', 0, true, false, false],
      ['sub.example.org: DE 1', 1, true, false, false],
      ['sub.example.org: FI 1', 1, true, true, false],
      ['Directly', 2, false, false, false],
      ['Block', 3, false, false, false],
    ]);
    expect(rule.outbounds[0].latency).toBe(120);
    expect(rule.route).toEqual({
      mode: 'auto',
      tier: 1,
      code: 'src1: FI 1',
      displayName: 'sub.example.org: FI 1',
      latency: 210,
    });
  });

  it('tells a pinned server, and the choice of a fallback whose turn has not come', async () => {
    mockModel({
      rules: [{ '.name': 'main' }],
      sources: [SUB],
      members: [{ section: 'main', role: 'server', source: 'src1' }],
    });
    mockProxies({
      'main-out': proxy('main-out', {
        type: 'Selector',
        now: 'b',
        all: ['main-urltest-out', 'a', 'b', 'c'],
      }),
      'main-urltest-out': proxy('main-urltest-out', {
        type: 'URLTest',
        now: 'a',
        all: ['a', 'main-fallback-1-out'],
        fallbacks: ['main-fallback-1-out'],
      }),
      'main-fallback-1-out': proxy('main-fallback-1-out', {
        type: 'URLTest',
        now: 'c',
        all: ['b', 'c'],
      }),
      a: proxy('a', { type: 'VLESS' }),
      b: proxy('b', { type: 'VLESS' }),
      c: proxy('c', { type: 'VLESS' }),
    });
    const [rule] = (await getDashboardSections()).data;
    expect(
      rule.outbounds.map((item) => [item.code, item.active, item.pick]),
    ).toEqual([
      ['a', false, false],
      ['b', true, false],
      ['c', false, true],
    ]);
    expect(rule.route).toMatchObject({ mode: 'manual', tier: 1, code: 'b' });
  });

  it('marks a server of the rule and of a fallback where the URL test went', async () => {
    mockModel({
      rules: [{ '.name': 'main' }],
      sources: [SUB],
      members: [{ section: 'main', role: 'server', source: 'src1' }],
    });
    mockProxies({
      'main-out': proxy('main-out', {
        type: 'Selector',
        now: 'main-urltest-out',
        all: ['main-urltest-out', 'a', 'b'],
      }),
      'main-urltest-out': proxy('main-urltest-out', {
        type: 'URLTest',
        now: 'main-fallback-1-out',
        all: ['a', 'main-fallback-1-out'],
        fallbacks: ['main-fallback-1-out'],
      }),
      'main-fallback-1-out': proxy('main-fallback-1-out', {
        type: 'URLTest',
        now: 'a',
        all: ['a', 'b'],
      }),
    });
    const [rule] = (await getDashboardSections()).data;
    expect(
      rule.outbounds.map((item) => [item.code, item.tier, item.active]),
    ).toEqual([
      ['a', 0, false],
      ['a', 1, true],
      ['b', 1, false],
    ]);
  });

  it('lays out by the selector an engine that does not list the fallbacks', async () => {
    mockModel({
      rules: [{ '.name': 'main' }],
      sources: [SUB],
      members: [{ section: 'main', role: 'server', source: 'src1' }],
    });
    mockProxies({
      'main-out': proxy('main-out', {
        type: 'Selector',
        now: 'main-urltest-out',
        all: ['main-urltest-out', 'a', 'main-fallback-1-out'],
      }),
      'main-urltest-out': proxy('main-urltest-out', {
        type: 'URLTest',
        now: 'a',
      }),
    });
    const [rule] = (await getDashboardSections()).data;
    expect(rule.tiers).toEqual([]);
    expect(rule.outbounds.map((item) => item.displayName)).toEqual([
      'a',
      'Fallback 1',
    ]);
  });

  it('names a rule without a label by its name', async () => {
    mockModel({
      rules: [{ '.name': 'youtube' }],
      sources: [SUB],
      members: [{ section: 'youtube', role: 'server', source: 'src1' }],
    });
    mockProxies({
      'youtube-out': proxy('youtube-out', {
        now: 'youtube-urltest-out',
        all: ['youtube-urltest-out'],
      }),
    });
    const result = await getDashboardSections();
    expect(result.data[0].displayName).toBe('youtube');
  });

  it('leaves out a disabled rule, a rule of direct or block, and one whose sources are not filled', async () => {
    mockModel({
      rules: [
        { '.name': 'off', enabled: '0' },
        { '.name': 'ru', label: 'Directly' },
        { '.name': 'ads' },
        { '.name': 'empty' },
        { '.name': 'main' },
      ],
      sources: [{ '.name': 'src9' }, SUB],
      members: [
        { section: 'off', role: 'server', source: 'src1' },
        { section: 'ru', role: 'server', source: 'direct' },
        { section: 'ads', role: 'server', source: 'block' },
        { section: 'empty', role: 'server', source: 'src9' },
        { section: 'main', role: 'server', source: 'src1' },
      ],
    });
    mockProxies({});
    const result = await getDashboardSections();
    expect(result.data.map((rule) => rule.code)).toEqual(['main-out']);
  });

  it('keeps a rule with direct only as a fallback', async () => {
    mockModel({
      rules: [{ '.name': 'main' }],
      sources: [SUB],
      members: [
        { section: 'main', role: 'server', source: 'src1' },
        { section: 'main', role: 'fallback', source: 'direct' },
      ],
    });
    mockProxies({});
    const result = await getDashboardSections();
    expect(result.data.map((rule) => rule.code)).toEqual(['main-out']);
  });

  it('shows no outbound of a rule the running configuration does not have', async () => {
    mockModel({
      rules: [{ '.name': 'main' }],
      sources: [SUB],
      members: [{ section: 'main', role: 'server', source: 'src1' }],
    });
    mockProxies({ 'direct-out': proxy('direct-out') });
    const result = await getDashboardSections();
    expect(result.data[0].withTagSelect).toBe(false);
    expect(result.data[0].outbounds).toEqual([]);
  });

  it('shows a rule whose sources name no server now as refused', async () => {
    mockModel({
      rules: [{ '.name': 'main' }],
      sources: [SUB],
      members: [{ section: 'main', role: 'server', source: 'src1' }],
    });
    mockProxies({
      'main-out': proxy('main-out', {
        type: 'Selector',
        now: 'block',
        all: ['block'],
      }),
      block: proxy('block', { type: 'Reject' }),
    });
    const result = await getDashboardSections();
    expect(
      result.data[0].outbounds.map((outbound) => [
        outbound.code,
        outbound.displayName,
        outbound.selected,
      ]),
    ).toEqual([['block', 'Refused: the rule has no server now', true]]);
  });

  it('fails when the Clash API does not answer', async () => {
    mockModel({});
    PodkopShellMethods.getClashApiProxies.mockResolvedValue({
      success: false,
      error: '',
    });
    expect(await getDashboardSections()).toEqual({ success: false, data: [] });
  });
});
