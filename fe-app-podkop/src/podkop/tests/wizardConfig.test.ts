import { describe, expect, it } from 'vitest';
import { buildConfig, type DnsValue } from '../wizard/config';
import { defaultSettings, type WizardSource } from '../wizard/importer';

const dns: DnsValue = {
  bootstrap: '77.88.8.8',
  servers: [
    { type: 'provider', server: 'ignored' },
    { type: 'doh', server: ' 1.1.1.1 ' },
  ],
  mode: 'order',
  addresses: 'prefer_ipv4',
  ttl: '60',
};

const subscription: WizardSource = {
  id: 7,
  kind: 'subscription',
  url: 'https://sub.example.org/api/TOKEN',
  settings: {
    ...defaultSettings(),
    agentPreset: 'happ',
    headers: 'X-Device: a\n\n',
  },
};
const links: WizardSource = {
  id: 9,
  kind: 'links',
  links: ['ss://a@1.2.3.4:1#One', 'ss://a@1.2.3.5:1#Two'],
  settings: { ...defaultSettings(), udpOverTcp: true, label: 'Mine' },
};

describe('the config the wizard writes', () => {
  it('names the sections by the first free names and keeps the order of the rules', () => {
    const config = buildConfig(
      [subscription, links],
      [
        {
          title: 'YouTube',
          enabled: true,
          lists: ['youtube'],
          mode: 'servers',
          rows: [
            { sourceId: 7, include: ['Германия'], exclude: [], protocols: [] },
          ],
        },
        {
          title: 'TikTok',
          enabled: false,
          lists: ['tiktok'],
          mode: 'block',
          rows: [{ sourceId: 7, include: [], exclude: [], protocols: [] }],
        },
        {
          title: 'Основное правило',
          enabled: true,
          lists: ['geoblock', 'telegram'],
          mode: 'servers',
          rows: [
            {
              sourceId: 7,
              include: [],
              exclude: ['ALT'],
              protocols: ['vless'],
            },
            { sourceId: 9, include: [], exclude: [], protocols: [] },
          ],
        },
      ],
      dns,
      ['src1', 'main', 'rule1'],
    );
    expect(config.sections).toEqual([
      {
        type: 'source',
        name: 'src2',
        options: {
          type: 'subscription',
          url: 'https://sub.example.org/api/TOKEN',
          user_agent_preset: 'happ',
          header: ['X-Device: a'],
        },
      },
      {
        type: 'source',
        name: 'src3',
        options: {
          type: 'links',
          label: 'Mine',
          link: ['ss://a@1.2.3.4:1#One', 'ss://a@1.2.3.5:1#Two'],
          udp_over_tcp: '1',
        },
      },
      {
        type: 'section',
        name: 'rule2',
        options: { label: 'YouTube', community_lists: ['youtube'] },
      },
      {
        type: 'member',
        options: {
          section: 'rule2',
          role: 'server',
          source: 'src2',
          include: ['Германия'],
        },
      },
      {
        type: 'section',
        name: 'rule3',
        options: { label: 'TikTok', enabled: '0', community_lists: ['tiktok'] },
      },
      {
        type: 'member',
        options: { section: 'rule3', role: 'server', source: 'block' },
      },
      {
        type: 'section',
        name: 'rule4',
        options: {
          label: 'Основное правило',
          community_lists: ['geoblock', 'telegram'],
        },
      },
      {
        type: 'member',
        options: {
          section: 'rule4',
          role: 'server',
          source: 'src2',
          exclude: ['ALT'],
          protocols: ['vless'],
        },
      },
      {
        type: 'member',
        options: { section: 'rule4', role: 'server', source: 'src3' },
      },
      { type: 'dns_server', options: { type: 'provider' } },
      { type: 'dns_server', options: { type: 'doh', server: '1.1.1.1' } },
    ]);
    expect(config.settings).toEqual({
      bootstrap_dns_server: '77.88.8.8',
      dns_mode: 'order',
      dns_addresses: 'prefer_ipv4',
      dns_rewrite_ttl: '60',
    });
  });

  it("writes podkop's own User-Agent as nothing, and an interface with its resolver", () => {
    const config = buildConfig(
      [
        { ...subscription, settings: defaultSettings() },
        {
          id: 2,
          kind: 'interface',
          iface: 'awg0',
          settings: {
            ...defaultSettings(),
            routingMark: ' 77 ',
            resolver: true,
            dnsType: 'doh',
            dnsServer: 'dns.example.org',
          },
        },
        {
          id: 3,
          kind: 'json',
          json: '{"type":"socks"}',
          settings: defaultSettings(),
        },
      ],
      [],
      dns,
    );
    expect(config.sections.slice(0, 3)).toEqual([
      {
        type: 'source',
        name: 'src1',
        options: {
          type: 'subscription',
          url: 'https://sub.example.org/api/TOKEN',
        },
      },
      {
        type: 'source',
        name: 'src2',
        options: {
          type: 'interface',
          interface: 'awg0',
          routing_mark: '77',
          domain_resolver_enabled: '1',
          domain_resolver_dns_type: 'doh',
          domain_resolver_dns_server: 'dns.example.org',
        },
      },
      {
        type: 'source',
        name: 'src3',
        options: { type: 'json', outbound_json: '{"type":"socks"}' },
      },
    ]);
  });
});
