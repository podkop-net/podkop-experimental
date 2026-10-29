import { PROXY_LINK_SCHEMES } from '../validators/validateProxyUrl';
import type { Podkop } from './types';

// The sources of servers (config source, tab Servers) and the rows of the rules (config
// member) as the page reads them: what a pasted text is, the names a source and its servers
// are shown by, which servers a row takes, and the rows the backend would refuse.

export const SOURCE_KINDS = [
  'subscription',
  'links',
  'json',
  'interface',
] as const;

export type SourceKind = (typeof SOURCE_KINDS)[number];

// the words a row names where it goes without a server; no source may be named so
export const ROW_DIRECT = 'direct';
export const ROW_BLOCK = 'block';
export const RESERVED_NAMES = [ROW_DIRECT, ROW_BLOCK];

// the items of a list option of UCI: an array, or one value
export function asList(value: unknown): string[] {
  const items = Array.isArray(value) ? value : value == null ? [] : [value];
  return items.map((item) => String(item).trim()).filter(Boolean);
}

// the links of a source of links: the backend splits the option by white space
export function sourceLinks(source?: Podkop.ConfigSource | null): string[] {
  return asList(source?.link).flatMap((item) => item.split(/\s+/));
}

export function sourceKind(
  source?: Podkop.ConfigSource | null,
): SourceKind | '' {
  const type = source?.type ?? '';
  return (SOURCE_KINDS as readonly string[]).includes(type)
    ? (type as SourceKind)
    : '';
}

// sourceFilled tells whether a source names servers, as the backend does (Source.Filled)
export function sourceFilled(source?: Podkop.ConfigSource | null): boolean {
  switch (sourceKind(source)) {
    case 'subscription':
      return !!String(source?.url ?? '').trim();
    case 'links':
      return sourceLinks(source).length > 0;
    case 'json':
      return !!String(source?.outbound_json ?? '').trim();
    case 'interface':
      return true;
  }
  return false;
}

// isMultiServer tells whether the rows of a source choose its servers by their names: a
// subscription, or several links (the backend filters only these)
export function isMultiServer(source?: Podkop.ConfigSource | null): boolean {
  const kind = sourceKind(source);
  return (
    kind === 'subscription' ||
    (kind === 'links' && sourceLinks(source).length > 1)
  );
}

function linkScheme(link: string): string {
  return link.includes('://')
    ? link.slice(0, link.indexOf('://')).toLowerCase()
    : '';
}

function decoded(text: string): string {
  try {
    return decodeURIComponent(text);
  } catch (_e) {
    return text;
  }
}

// linkHost is the server of a link as host:port, '' when the link does not show it
export function linkHost(link: string): string {
  const match = link.match(
    /^[a-z0-9+.-]+:\/\/(?:[^@/?#]*@)?(\[[^\]]+\]|[^:/?#]+)(?::(\d+))?/i,
  );
  if (!match || !link.slice(link.indexOf('://') + 3).includes('@')) {
    // vmess:// and ss:// may keep the server inside base64
    if (!match || ['vmess', 'ss'].includes(linkScheme(link))) return '';
  }
  return match[1] + (match[2] ? ':' + match[2] : '');
}

// linkName is the name of a link after #, the name the backend filters it by
export function linkName(link: string): string {
  const hash = link.indexOf('#');
  return hash >= 0 ? decoded(link.slice(hash + 1)).trim() : '';
}

// the host of an address, '' when it is not one
function hostOf(address: string): string {
  try {
    return new URL(address).hostname;
  } catch (_e) {
    return '';
  }
}

// the outbound of an outbound JSON, null when it is not one object
function parseOutbound(text: string): Record<string, unknown> | null {
  try {
    const value = JSON.parse(String(text ?? '').replace(/^\uFEFF/, ''));
    return value && typeof value === 'object' && !Array.isArray(value)
      ? value
      : null;
  } catch (_e) {
    return null;
  }
}

// sourceAutoLabel is the name the page gives a source without a label of its own: the host
// of a subscription, the name of the one link, the tag of the outbound, the interface
export function sourceAutoLabel(source: Podkop.ConfigSource): string {
  const name = source['.name'];
  switch (sourceKind(source)) {
    case 'subscription':
      return hostOf(String(source.url ?? '').trim()) || name;
    case 'links': {
      const links = sourceLinks(source);
      if (links.length === 1) {
        return (
          linkName(links[0]) ||
          [linkScheme(links[0]), linkHost(links[0])]
            .filter(Boolean)
            .join(' ') ||
          name
        );
      }
      return links.length ? _('My servers (%d)').format(links.length) : name;
    }
    case 'json': {
      const outbound = parseOutbound(String(source.outbound_json ?? ''));
      const tag = outbound?.tag ?? outbound?.type;
      return typeof tag === 'string' && tag ? tag : name;
    }
    case 'interface':
      return source.interface || _('Main route');
  }
  return name;
}

export function sourceLabel(source: Podkop.ConfigSource): string {
  return String(source.label ?? '').trim() || sourceAutoLabel(source);
}

// The names of the servers of a source of links, as the backend filters them
export function sourceServerNames(source: Podkop.ConfigSource): string[] {
  return sourceLinks(source).map(linkName);
}

// nameHas tells whether a word of the name starts with the word: "AI" finds "USA AI-1" and
// not "Spain". A word with other characters than letters and digits (a flag, a dash, a
// space) is looked for in the name as it is. As the backend does (model.NameHas).
export function nameHas(name: string, word: string): boolean {
  const lowName = String(name).toLowerCase();
  const lowWord = String(word).trim().toLowerCase();
  if (!lowWord) return false;
  if (/[^\p{L}\p{Nd}]/u.test(lowWord)) return lowName.includes(lowWord);
  return lowName
    .split(/[^\p{L}\p{Nd}]+/u)
    .some((part) => part.startsWith(lowWord));
}

// rowTakes tells whether a row with these words takes a server of the name
export function rowTakes(
  name: string,
  include: string[],
  exclude: string[],
): boolean {
  if (exclude.some((word) => nameHas(name, word))) return false;
  return !include.length || include.some((word) => nameHas(name, word));
}

// filterWords splits the text of a filter field into its words: by commas
export function filterWords(text: unknown): string[] {
  return asList(text)
    .flatMap((item) => item.split(','))
    .map((item) => item.trim())
    .filter(Boolean);
}

// What a pasted text is: a subscription, links of servers, an outbound JSON, or why none.
export interface PastedText {
  kind: SourceKind | 'error' | '';
  url?: string;
  links?: string[];
  json?: string;
  // what was found, and a note on it
  title: string;
  note?: string;
}

// the links of apps that add a subscription: the address is inside
const WRAPPERS: [RegExp, string][] = [
  [/^happ:\/\/add\/(.+)$/i, 'Happ'],
  [/^hiddify:\/\/import\/(.+)$/i, 'Hiddify'],
  [/^streisand:\/\/import\/(.+)$/i, 'Streisand'],
  [/^v2rayng:\/\/install-config\?url=([^&#]+)/i, 'v2rayNG'],
  [/^clash:\/\/install-config\?url=([^&#]+)/i, 'Clash'],
  [/^sing-box:\/\/import-remote-profile\?url=([^&#]+)/i, 'sing-box'],
];

// unwrapSubscription takes the address of a subscription out of the link of an app that
// adds it; null when the text is not such a link
export function unwrapSubscription(
  text: string,
): { url: string; app: string } | null {
  const trimmed = String(text ?? '').trim();
  for (const [pattern, app] of WRAPPERS) {
    const match = trimmed.match(pattern);
    if (!match) continue;
    const url = decoded(match[1]).trim();
    if (/^https?:\/\/\S+$/i.test(url)) return { url, app };
  }
  return null;
}

// an HTTP proxy with a user: http(s)://user:password@host:port, not a subscription
function isHttpProxy(line: string): boolean {
  return /^https?:\/\/[^@/?#\s]+@[^:/?#\s]+(?::\d+)?\/?$/i.test(line);
}

function isServerLink(line: string): boolean {
  const scheme = linkScheme(line);
  if (scheme === 'http' || scheme === 'https') return isHttpProxy(line);
  return PROXY_LINK_SCHEMES.includes(scheme);
}

// the text of base64 (of a list of a provider, say), '' when it is not base64
function fromBase64(text: string): string {
  const compact = text
    .replace(/\s+/g, '')
    .replace(/-/g, '+')
    .replace(/_/g, '/');
  if (!compact || !/^[A-Za-z0-9+/]+=*$/.test(compact)) return '';
  try {
    const padded = compact + '='.repeat((4 - (compact.length % 4)) % 4);
    const binary = atob(padded);
    return new TextDecoder().decode(
      Uint8Array.from(binary, (char) => char.charCodeAt(0)),
    );
  } catch (_e) {
    return '';
  }
}

function linksFound(links: string[], note?: string): PastedText {
  const schemes = [...new Set(links.map(linkScheme))].join(', ');
  return {
    kind: 'links',
    links,
    title:
      links.length === 1
        ? _('Server link: %s').format(
            [schemes, linkHost(links[0])].filter(Boolean).join(', '),
          )
        : _('Server links: %d (%s)').format(links.length, schemes),
    note,
  };
}

// detectPasted tells what a pasted text is
export function detectPasted(text: string): PastedText {
  const trimmed = String(text ?? '')
    .replace(/^\uFEFF/, '')
    .trim();
  if (!trimmed) return { kind: '', title: '' };

  const wrapped = unwrapSubscription(trimmed);
  if (wrapped) {
    return {
      kind: 'subscription',
      url: wrapped.url,
      title: _('Subscription: %s').format(hostOf(wrapped.url)),
      note: _('The address is taken from the link that adds it to %s').format(
        wrapped.app,
      ),
    };
  }
  if (/^happ:\/\/crypt/i.test(trimmed)) {
    return {
      kind: 'error',
      title: _('An encrypted link of Happ'),
      note: _(
        'Only Happ opens it. Paste the plain subscription address https://… from the account at your provider',
      ),
    };
  }
  if (/^vpn:\/\//i.test(trimmed)) {
    return {
      kind: 'error',
      title: _('A key of AmneziaVPN'),
      note: _(
        'Make an AmneziaWG interface in Network, Interfaces, then choose the type Interface here',
      ),
    };
  }
  if (/^ssconf:\/\//i.test(trimmed)) {
    const url = 'https://' + trimmed.slice('ssconf://'.length);
    return {
      kind: 'subscription',
      url,
      title: _('Subscription: %s').format(hostOf(url)),
      note: _('A dynamic key of Outline: it is loaded as a subscription'),
    };
  }
  if (trimmed[0] === '{' || trimmed[0] === '[') {
    let value: unknown;
    try {
      value = JSON.parse(trimmed);
    } catch (err) {
      return {
        kind: 'error',
        title: _('Invalid JSON format'),
        note: String((err as Error)?.message ?? err),
      };
    }
    if (Array.isArray(value)) {
      return {
        kind: 'error',
        title: _('A list of outbounds'),
        note: _('One outbound is expected: {"type": "vless", …}'),
      };
    }
    const outbound = value as Record<string, unknown>;
    if (outbound && 'outbounds' in outbound) {
      return {
        kind: 'error',
        title: _('A whole configuration of sing-box'),
        note: _('One outbound is expected: {"type": "vless", …}'),
      };
    }
    if (!outbound || typeof outbound.type !== 'string' || !outbound.type) {
      return {
        kind: 'error',
        title: _('The JSON has no field type'),
        note: _('An outbound of sing-box is expected: {"type": "vless", …}'),
      };
    }
    const server =
      typeof outbound.server === 'string'
        ? outbound.server +
          (outbound.server_port ? ':' + outbound.server_port : '')
        : '';
    return {
      kind: 'json',
      json: trimmed,
      title: _('Outbound JSON: %s').format(
        [outbound.type, server].filter(Boolean).join(', '),
      ),
    };
  }

  const lines = trimmed.split(/\s+/).filter(Boolean);
  if (lines.length === 1 && /^https?:\/\//i.test(trimmed)) {
    if (isHttpProxy(trimmed)) {
      return linksFound(
        lines,
        _('An HTTP proxy. If it is a subscription, choose the type by hand'),
      );
    }
    return {
      kind: 'subscription',
      url: trimmed,
      title: _('Subscription: %s').format(hostOf(trimmed)),
    };
  }
  const links = lines.filter(isServerLink);
  if (links.length && links.length === lines.length) {
    return linksFound(links);
  }
  if (links.length) {
    const other = lines.filter((line) => !isServerLink(line));
    return {
      kind: 'error',
      title: _('Not recognized'),
      note: _('These are not links of servers: %s').format(
        other
          .slice(0, 3)
          .map((line) => line.slice(0, 24))
          .join(', '),
      ),
    };
  }
  const decodedText = fromBase64(trimmed);
  if (decodedText.includes('://')) {
    const decodedLines = decodedText.split(/\s+/).filter(Boolean);
    const decodedLinks = decodedLines.filter(isServerLink);
    if (decodedLinks.length) {
      return linksFound(decodedLinks, _('The text was decoded from base64'));
    }
  }
  return {
    kind: 'error',
    title: _('Not recognized'),
    note: _('Check that the text is copied whole, or choose the type by hand'),
  };
}

// validateRoutingMark checks a routing mark of an interface: a number whose bits are not
// the marks of podkop (0x200000, 0x400000) or the mask of mwan3 (0x3F00); '' when it is fine
export function validateRoutingMark(value: string): string {
  const text = String(value ?? '').trim();
  if (!text) return '';
  const number = /^0x[0-9a-f]+$/i.test(text)
    ? parseInt(text, 16)
    : /^\d+$/.test(text)
      ? parseInt(text, 10)
      : NaN;
  if (isNaN(number) || number <= 0 || number > 0xffffffff) {
    return _('A number is expected, as 0x10000');
  }
  if (number & 0x600000) {
    return _('The bits 0x200000 and 0x400000 are the marks of podkop');
  }
  if (number & 0x3f00) {
    return _('The bits 0x3F00 are the mask of mwan3');
  }
  return '';
}

// Where the traffic of a rule goes, as the backend tells it (Config.Exit): 'direct' or
// 'block' (its one row of the servers is that), 'servers' (an outbound of its own), or ''
// (no row names a filled source yet: the rule does nothing)
export function ruleExit(
  rule: Podkop.ConfigRule,
  sources: Podkop.ConfigSource[],
  members: Podkop.ConfigMember[],
): 'direct' | 'block' | 'servers' | '' {
  const rows = members.filter((row) => row.section === rule['.name']);
  const servers = rows.filter((row) => row.role !== 'fallback');
  const fallbacks = rows.filter((row) => row.role === 'fallback');
  if (servers.length === 1 && !fallbacks.length) {
    if (servers[0].source === ROW_DIRECT) return 'direct';
    if (servers[0].source === ROW_BLOCK) return 'block';
  }
  for (const row of [...servers, ...fallbacks]) {
    if (row.source === ROW_DIRECT || row.source === ROW_BLOCK) {
      return 'servers';
    }
    const source = sources.find((item) => item['.name'] === row.source);
    if (sourceFilled(source)) return 'servers';
  }
  return '';
}

// A row of a rule the backend would refuse the whole configuration for
export interface RowProblem {
  rule: string;
  role: 'server' | 'fallback';
  // the place of the row among the rows of its role, from 1
  index: number;
  error: string;
}

// ruleRowProblems lists the rows of the enabled rules whose "through" the backend refuses:
// a source that is not there, not filled, the row's own source, or a row of an interface
export function ruleRowProblems(
  rules: Podkop.ConfigRule[],
  sources: Podkop.ConfigSource[],
  members: Podkop.ConfigMember[],
): RowProblem[] {
  const problems: RowProblem[] = [];
  const find = (name?: string) =>
    sources.find((item) => item['.name'] === name);
  for (const rule of rules) {
    if (rule.enabled === '0') continue;
    if (ruleExit(rule, sources, members) !== 'servers') continue;
    for (const role of ['server', 'fallback'] as const) {
      const rows = members.filter(
        (row) =>
          row.section === rule['.name'] &&
          (row.role === 'fallback') === (role === 'fallback'),
      );
      rows.forEach((row, index) => {
        const via = String(row.via ?? '').trim();
        const source = find(row.source);
        if (!via || !source || !sourceFilled(source)) return;
        let error = '';
        if (sourceKind(source) === 'interface') {
          error = _('An interface does not connect through another source');
        } else if (via === row.source) {
          error = _('The row connects through its own source');
        } else if (!find(via)) {
          error = _('The source %s to connect through is deleted').format(via);
        } else if (!sourceFilled(find(via))) {
          error = _('The source %s to connect through is not filled').format(
            sourceLabel(find(via)!),
          );
        }
        if (error)
          problems.push({ rule: rule['.name'], role, index: index + 1, error });
      });
    }
  }
  return problems;
}

// serverDisplayName names an outbound of a server by the labels of the sources: its tag is
// "<source>", "<source>: <name>", with " via <source>" for a row that connects through one
export function serverDisplayName(
  tag: string,
  sources: Podkop.ConfigSource[],
): string {
  const byName = (name: string) =>
    sources.find((source) => source['.name'] === name);
  let base = tag;
  let through = '';
  const via = tag.match(/^(.*) via ([A-Za-z0-9_]+)$/);
  if (via && byName(via[2])) {
    base = via[1];
    through = sourceLabel(byName(via[2])!);
  }
  let shown = base;
  const own = byName(base);
  if (own) {
    shown = sourceLabel(own);
  } else {
    const colon = base.indexOf(': ');
    const source = colon > 0 ? byName(base.slice(0, colon)) : undefined;
    if (source) shown = sourceLabel(source) + base.slice(colon);
  }
  return through ? _('%s via %s').format(shown, through) : shown;
}
