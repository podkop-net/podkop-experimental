import { describe, expect, it } from 'vitest';
import {
  detectPasted,
  filterWords,
  isMultiServer,
  nameHas,
  rowTakes,
  ruleExit,
  ruleRowProblems,
  serverDisplayName,
  sourceAutoLabel,
  sourceFilled,
  sourceLabel,
  unwrapSubscription,
  validateRoutingMark,
} from '../sources';

const SUB_URL = 'https://sub.labvpn.example/api/sub/Q2xhdWRlUHJvdG8';
const VLESS =
  'vless://6f1c9a0e-3b52-4c1e-9a55-2d4a1b0f7c11@203.0.113.7:443?type=tcp&security=reality&fp=chrome&sni=www.example.com#%F0%9F%87%B3%F0%9F%87%B1%20My%20VPS';
const HY2 = 'hy2://lab@203.0.113.22:443?sni=www.example.com#Helsinki';
const TROJAN = 'trojan://pass@203.0.113.23:443?sni=www.example.com#Warsaw';

describe('detectPasted', () => {
  it('takes an address of https for a subscription', () => {
    expect(detectPasted(`  ${SUB_URL}\n`)).toMatchObject({
      kind: 'subscription',
      url: SUB_URL,
    });
  });

  it('takes the address out of the links of apps that add a subscription', () => {
    expect(detectPasted(`happ://add/${SUB_URL}`)).toMatchObject({
      kind: 'subscription',
      url: SUB_URL,
    });
    expect(
      detectPasted(
        `v2rayng://install-config?url=${encodeURIComponent(SUB_URL)}#name`,
      ),
    ).toMatchObject({ kind: 'subscription', url: SUB_URL });
    expect(unwrapSubscription(`hiddify://import/${SUB_URL}`)).toEqual({
      url: SUB_URL,
      app: 'Hiddify',
    });
    expect(unwrapSubscription('happ://add/not-an-address')).toBeNull();
  });

  it('tells why an encrypted link of Happ and a key of Amnezia cannot be used', () => {
    const crypt = detectPasted('happ://crypt3/Xk2vLq9P0aZt7Hc1Wm4Rb8Ns5Ue3Yo6');
    expect(crypt.kind).toBe('error');
    expect(crypt.note).toContain('https://');
    const amnezia = detectPasted('vpn://AAAB3nicbVBNT8MwDP0rVc5I4yDHZ');
    expect(amnezia.kind).toBe('error');
    expect(amnezia.note).toContain('Interface');
  });

  it('takes links of servers, one or several, by white space', () => {
    expect(detectPasted(VLESS)).toMatchObject({
      kind: 'links',
      links: [VLESS],
    });
    expect(detectPasted(`${VLESS}\n${HY2}\r\n\n${TROJAN}`)).toMatchObject({
      kind: 'links',
      links: [VLESS, HY2, TROJAN],
    });
  });

  it('takes links in base64, as a provider sends them', () => {
    const text = Buffer.from(`${VLESS}\n${HY2}\n`).toString('base64');
    expect(detectPasted(text)).toMatchObject({
      kind: 'links',
      links: [VLESS, HY2],
    });
  });

  it('takes an HTTP proxy with a user for a link, not a subscription', () => {
    expect(detectPasted('http://user:pass@192.0.2.5:3128')).toMatchObject({
      kind: 'links',
    });
  });

  it('refuses a text with something else among the links', () => {
    expect(detectPasted(`${VLESS}\nhello`).kind).toBe('error');
    expect(detectPasted('hello world').kind).toBe('error');
    expect(detectPasted(`${SUB_URL}\n${SUB_URL}`).kind).toBe('error');
  });

  it('takes one outbound JSON and refuses a configuration or a list', () => {
    const json =
      '{"type": "trojan", "server": "198.51.100.4", "server_port": 443}';
    expect(detectPasted(json)).toMatchObject({ kind: 'json', json });
    expect(detectPasted('{"outbounds": []}').kind).toBe('error');
    expect(detectPasted('[{"type": "direct"}]').kind).toBe('error');
    expect(detectPasted('{"tag": "x"}').kind).toBe('error');
    expect(detectPasted('{"type": ').kind).toBe('error');
  });

  it('finds nothing in nothing', () => {
    expect(detectPasted('  \n ').kind).toBe('');
  });
});

describe('nameHas and rowTakes', () => {
  it('finds the start of a word, in any case', () => {
    expect(nameHas('🇺🇸 USA AI-1', 'AI')).toBe(true);
    expect(nameHas('🇪🇸 Spain', 'AI')).toBe(false);
    expect(nameHas('🇳🇱 Netherlands 2', 'nether')).toBe(true);
  });

  it('looks for a word with a flag, a dash or a space as it is', () => {
    expect(nameHas('🇺🇸 USA AI-1', 'AI-1')).toBe(true);
    expect(nameHas('🇺🇸 USA 1', '🇺🇸')).toBe(true);
    expect(nameHas('USA 1', 'a 1')).toBe(true);
    expect(nameHas('USA 1', '  ')).toBe(false);
  });

  it('takes every server without words, none of the excluded', () => {
    expect(rowTakes('NL 1', [], [])).toBe(true);
    expect(rowTakes('NL AI', ['NL'], ['AI'])).toBe(false);
    expect(rowTakes('DE 1', ['NL', 'DE'], [])).toBe(true);
    expect(rowTakes('FR 1', ['NL', 'DE'], [])).toBe(false);
  });

  it('splits the text of a filter by commas', () => {
    expect(filterWords('USA, AI-1 ,, 🇳🇱')).toEqual(['USA', 'AI-1', '🇳🇱']);
    expect(filterWords(['NL', ' DE '])).toEqual(['NL', 'DE']);
    expect(filterWords(undefined)).toEqual([]);
  });
});

describe('the names of the sources', () => {
  it('names a source by its label, else by what it holds', () => {
    expect(
      sourceLabel({
        '.name': 'src1',
        type: 'subscription',
        url: SUB_URL,
        label: ' Lab ',
      }),
    ).toBe('Lab');
    expect(
      sourceAutoLabel({ '.name': 'src1', type: 'subscription', url: SUB_URL }),
    ).toBe('sub.labvpn.example');
    expect(
      sourceAutoLabel({ '.name': 'src2', type: 'links', link: [VLESS] }),
    ).toBe('🇳🇱 My VPS');
    expect(
      sourceAutoLabel({ '.name': 'src2', type: 'links', link: [VLESS, HY2] }),
    ).toBe('My servers (2)');
    expect(
      sourceAutoLabel({
        '.name': 'src3',
        type: 'json',
        outbound_json: '{"type":"trojan","tag":"my-trojan"}',
      }),
    ).toBe('my-trojan');
    expect(
      sourceAutoLabel({
        '.name': 'src4',
        type: 'interface',
        interface: 'awg0',
      }),
    ).toBe('awg0');
    expect(sourceAutoLabel({ '.name': 'src4', type: 'interface' })).toBe(
      'Main route',
    );
    expect(sourceAutoLabel({ '.name': 'src5' })).toBe('src5');
  });

  it('tells a filled source and one of several servers', () => {
    expect(sourceFilled({ '.name': 'a' })).toBe(false);
    expect(sourceFilled({ '.name': 'a', type: 'subscription', url: ' ' })).toBe(
      false,
    );
    expect(sourceFilled({ '.name': 'a', type: 'interface' })).toBe(true);
    expect(isMultiServer({ '.name': 'a', type: 'links', link: [VLESS] })).toBe(
      false,
    );
    expect(
      isMultiServer({ '.name': 'a', type: 'links', link: `${VLESS} ${HY2}` }),
    ).toBe(true);
    expect(isMultiServer({ '.name': 'a', type: 'subscription' })).toBe(true);
  });

  it('names the outbounds of servers by the labels of their sources', () => {
    const sources = [
      { '.name': 'src1', type: 'subscription', url: SUB_URL, label: 'Lab' },
      { '.name': 'src2', type: 'links', link: [HY2] },
      { '.name': 'src3', type: 'interface', interface: 'awg0', label: 'WARP' },
    ];
    expect(serverDisplayName('src1: 🇺🇸 USA AI-1', sources)).toBe(
      'Lab: 🇺🇸 USA AI-1',
    );
    expect(serverDisplayName('src1: USA via src3', sources)).toBe(
      'Lab: USA via WARP',
    );
    expect(serverDisplayName('src2', sources)).toBe('Helsinki');
    expect(serverDisplayName('other: x', sources)).toBe('other: x');
  });
});

describe('validateRoutingMark', () => {
  it('takes a number whose bits are free', () => {
    expect(validateRoutingMark('')).toBe('');
    expect(validateRoutingMark('0x10000')).toBe('');
    expect(validateRoutingMark('65536')).toBe('');
  });

  it('refuses what is no number and the bits of podkop and mwan3', () => {
    expect(validateRoutingMark('mark')).not.toBe('');
    expect(validateRoutingMark('0')).not.toBe('');
    expect(validateRoutingMark('0x200000')).not.toBe('');
    expect(validateRoutingMark('0x400000')).not.toBe('');
    expect(validateRoutingMark('0x100')).not.toBe('');
  });
});

describe('ruleExit and ruleRowProblems', () => {
  const sources = [
    { '.name': 'src1', type: 'subscription', url: SUB_URL },
    { '.name': 'src2' },
    { '.name': 'src3', type: 'interface', interface: 'awg0' },
  ];

  it('tells where a rule goes as the backend does', () => {
    const exit = (members: object[]) =>
      ruleExit({ '.name': 'r' }, sources, members as never);
    expect(exit([{ section: 'r', source: 'direct' }])).toBe('direct');
    expect(exit([{ section: 'r', role: 'server', source: 'block' }])).toBe(
      'block',
    );
    expect(
      exit([
        { section: 'r', source: 'direct' },
        { section: 'r', role: 'fallback', source: 'block' },
      ]),
    ).toBe('servers');
    expect(exit([{ section: 'r', source: 'src2' }])).toBe('');
    expect(exit([{ section: 'r', source: 'gone' }])).toBe('');
    expect(exit([{ section: 'r', source: 'src1' }])).toBe('servers');
    expect(exit([])).toBe('');
  });

  it('lists the rows the backend would refuse for their "through"', () => {
    const rules = [{ '.name': 'r' }, { '.name': 'off', enabled: '0' }];
    const members = [
      { section: 'r', role: 'server', source: 'src1', via: 'src3' },
      { section: 'r', role: 'server', source: 'src1', via: 'gone' },
      { section: 'r', role: 'server', source: 'src1', via: 'src1' },
      { section: 'r', role: 'fallback', source: 'src1', via: 'src2' },
      { section: 'r', role: 'fallback', source: 'src3', via: 'src1' },
      { section: 'r', role: 'fallback', source: 'src2', via: 'gone' },
      { section: 'off', role: 'server', source: 'src1', via: 'gone' },
    ];
    expect(
      ruleRowProblems(rules, sources, members as never).map((problem) => [
        problem.rule,
        problem.role,
        problem.index,
      ]),
    ).toEqual([
      ['r', 'server', 2],
      ['r', 'server', 3],
      ['r', 'fallback', 1],
      ['r', 'fallback', 2],
    ]);
  });
});
