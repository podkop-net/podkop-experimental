import { beforeEach, describe, expect, it, vi } from 'vitest';
import { getDashboardSections } from '../getDashboardSections';
import { getConfigSections } from '../getConfigSections';
import { PodkopShellMethods } from '../../shell';

vi.mock('../getConfigSections', () => ({ getConfigSections: vi.fn() }));
// the helpers index pulls in the DOM services: only the two helpers used here
vi.mock('../../../../helpers', async () => ({
  getProxyUrlName: (await import('../../../../helpers/getProxyUrlName'))
    .getProxyUrlName,
  splitProxyString: (await import('../../../../helpers/splitProxyString'))
    .splitProxyString,
}));
vi.mock('../../shell', () => ({
  PodkopShellMethods: { getClashApiProxies: vi.fn() },
}));

const proxy = (name, extra = {}) => ({ name, history: [], ...extra });

function mockUrlTest(section, all) {
  getConfigSections.mockResolvedValue([section]);
  PodkopShellMethods.getClashApiProxies.mockResolvedValue({
    success: true,
    data: {
      proxies: {
        'main-out': proxy('main-out', { now: 'main-urltest-out' }),
        'main-urltest-out': proxy('main-urltest-out', { all }),
        ...Object.fromEntries(all.map((tag) => [tag, proxy(tag)])),
      },
    },
  });
}

async function tileNames() {
  const result = await getDashboardSections();
  return result.data[0].outbounds.map((outbound) => outbound.displayName);
}

describe('getDashboardSections, urltest section', () => {
  beforeEach(() => vi.clearAllMocks());

  it('names the proxy links, then the fallback links, in the group order', async () => {
    mockUrlTest(
      {
        '.name': 'main',
        connection_type: 'proxy',
        proxy_config_type: 'urltest',
        urltest_proxy_links: [
          'socks5://10.0.0.1:1080#A',
          'socks5://10.0.0.2:1080#B',
        ],
        urltest_fallback_links: ['socks5://10.0.0.3:1080#Fallback'],
      },
      ['main-1-out', 'main-2-out', 'main-fallback-1-out'],
    );

    expect(await tileNames()).toEqual(['Fastest', 'A', 'B', 'Fallback']);
  });

  it('names the proxy links when there are no fallback links', async () => {
    mockUrlTest(
      {
        '.name': 'main',
        connection_type: 'proxy',
        proxy_config_type: 'urltest',
        urltest_proxy_links: [
          'socks5://10.0.0.1:1080#A',
          'socks5://10.0.0.2:1080#B',
        ],
      },
      ['main-1-out', 'main-2-out'],
    );

    expect(await tileNames()).toEqual(['Fastest', 'A', 'B']);
  });

  it('falls back to the outbound name for a link without a name', async () => {
    mockUrlTest(
      {
        '.name': 'main',
        connection_type: 'proxy',
        proxy_config_type: 'urltest',
        urltest_proxy_links: ['socks5://10.0.0.1:1080#A'],
        urltest_fallback_links: ['socks5://10.0.0.3:1080'],
      },
      ['main-1-out', 'main-fallback-1-out'],
    );

    expect(await tileNames()).toEqual(['Fastest', 'A', 'main-fallback-1-out']);
  });
});

describe('getDashboardSections, a section that connects through another', () => {
  beforeEach(() => vi.clearAllMocks());

  it('tells the section it goes through, and only for a proxy section', async () => {
    getConfigSections.mockResolvedValue([
      {
        '.name': 'main',
        '.type': 'section',
        connection_type: 'proxy',
        proxy_config_type: 'url',
        proxy_string: 'socks5://203.0.113.15:1080',
        detour: 'entry',
      },
      {
        '.name': 'entry',
        '.type': 'section',
        connection_type: 'proxy',
        proxy_config_type: 'url',
        proxy_string: 'socks5://203.0.113.16:1080',
      },
      {
        '.name': 'awg',
        '.type': 'section',
        connection_type: 'vpn',
        interface: 'awg0',
        detour: 'entry',
      },
    ]);
    PodkopShellMethods.getClashApiProxies.mockResolvedValue({
      success: true,
      data: {
        proxies: {
          'main-out': proxy('main-out'),
          'entry-out': proxy('entry-out'),
          'awg-out': proxy('awg-out'),
        },
      },
    });
    const result = await getDashboardSections();
    expect(result.data.map((group) => group.detour)).toEqual([
      'entry',
      undefined,
      undefined,
    ]);
  });
});

describe('getDashboardSections, group section', () => {
  beforeEach(() => vi.clearAllMocks());

  it('shows the test of the group first, then its servers by their tags', async () => {
    getConfigSections.mockResolvedValue([
      { '.name': 'youtube', connection_type: 'group', group: 'nl' },
    ]);
    PodkopShellMethods.getClashApiProxies.mockResolvedValue({
      success: true,
      data: {
        proxies: {
          'youtube-out': proxy('youtube-out', {
            type: 'Selector',
            now: 'nl-group',
            all: ['nl-group', 'prov1: NL 1', 'prov1: NL 2'],
          }),
          'nl-group': proxy('nl-group', { type: 'URLTest' }),
          'prov1: NL 1': proxy('prov1: NL 1', { type: 'VLESS' }),
          'prov1: NL 2': proxy('prov1: NL 2', { type: 'VLESS' }),
        },
      },
    });

    const result = await getDashboardSections();
    expect(result.data[0].withTagSelect).toBe(true);
    expect(result.data[0].code).toBe('youtube-out');
    expect(
      result.data[0].outbounds.map((outbound) => outbound.displayName),
    ).toEqual(['Fastest', 'prov1: NL 1', 'prov1: NL 2']);
    expect(result.data[0].outbounds[0].selected).toBe(true);
  });

  it('shows no server of a group the running configuration does not have', async () => {
    getConfigSections.mockResolvedValue([
      { '.name': 'youtube', connection_type: 'group', group: 'nl' },
    ]);
    PodkopShellMethods.getClashApiProxies.mockResolvedValue({
      success: true,
      data: { proxies: { 'direct-out': proxy('direct-out') } },
    });

    const result = await getDashboardSections();
    expect(result.data[0].outbounds).toEqual([]);
  });

  it('shows a group that chose no server and refuses as refused', async () => {
    getConfigSections.mockResolvedValue([
      { '.name': 'youtube', connection_type: 'group', group: 'nl' },
    ]);
    PodkopShellMethods.getClashApiProxies.mockResolvedValue({
      success: true,
      data: {
        proxies: {
          'youtube-out': proxy('youtube-out', {
            type: 'Selector',
            now: 'block',
            all: ['block'],
          }),
          block: proxy('block', { type: 'Reject' }),
        },
      },
    });

    const result = await getDashboardSections();
    expect(result.data[0].code).toBe('youtube-out');
    expect(
      result.data[0].outbounds.map((outbound) => [
        outbound.code,
        outbound.displayName,
        outbound.selected,
      ]),
    ).toEqual([['block', 'Refused: the group has no server', true]]);
  });

  it('shows a group that goes as the section named block as that section', async () => {
    getConfigSections.mockResolvedValue([
      { '.name': 'youtube', connection_type: 'group', group: 'nl' },
      { '.name': 'block', connection_type: 'proxy' },
    ]);
    PodkopShellMethods.getClashApiProxies.mockResolvedValue({
      success: true,
      data: {
        proxies: {
          'youtube-out': proxy('youtube-out', {
            type: 'Selector',
            now: 'block-out',
            all: ['block-out'],
          }),
          'block-out': proxy('block-out', { type: 'Socks' }),
        },
      },
    });

    const result = await getDashboardSections();
    expect(
      result.data[0].outbounds.map((outbound) => outbound.displayName),
    ).toEqual(['block-out']);
  });
});
