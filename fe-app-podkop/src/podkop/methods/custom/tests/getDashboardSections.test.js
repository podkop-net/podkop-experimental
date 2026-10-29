import { beforeEach, describe, expect, it, vi } from 'vitest';
import { getDashboardSections } from '../getDashboardSections';
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

  it('shows the test of a rule first, then its servers by the labels of their sources, then its fallback tiers', async () => {
    mockModel({
      rules: [{ '.name': 'main', label: 'Main' }],
      sources: [SUB, ONE, WARP],
      members: [
        { section: 'main', role: 'server', source: 'src1', via: 'src3' },
        { section: 'main', role: 'server', source: 'src2' },
        { section: 'main', role: 'fallback', source: 'src1' },
        { section: 'main', role: 'fallback', source: 'direct' },
      ],
    });
    const all = [
      'main-urltest-out',
      'src1: NL 1 via src3',
      'src2',
      'main-fallback-1-out',
    ];
    mockProxies({
      'main-out': proxy('main-out', {
        type: 'Selector',
        now: 'main-urltest-out',
        all,
      }),
      'main-urltest-out': proxy('main-urltest-out', { type: 'URLTest' }),
      'src1: NL 1 via src3': proxy('src1: NL 1 via src3', {
        type: 'VLESS',
        history: [{ delay: 120 }],
      }),
      src2: proxy('src2', { type: 'Hysteria2' }),
      'main-fallback-1-out': proxy('main-fallback-1-out', { type: 'URLTest' }),
    });

    const result = await getDashboardSections();
    expect(result.success).toBe(true);
    expect(result.data).toHaveLength(1);
    const [rule] = result.data;
    expect(rule.withTagSelect).toBe(true);
    expect(rule.code).toBe('main-out');
    expect(rule.displayName).toBe('Main');
    expect(rule.outbounds.map((outbound) => outbound.displayName)).toEqual([
      'Fastest',
      'sub.example.org: NL 1 via WARP',
      'Hetzner',
      'Fallback 1',
    ]);
    expect(rule.outbounds.map((outbound) => outbound.code)).toEqual(all);
    expect(rule.outbounds[0].selected).toBe(true);
    expect(rule.outbounds[1].latency).toBe(120);
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
