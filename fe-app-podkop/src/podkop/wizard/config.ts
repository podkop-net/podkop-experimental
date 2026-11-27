import { listRequest } from '../../validators/validateRequestHeader';
import type { WizardSource } from './importer';

// What the wizard writes to the router: the sections of /etc/config/podkop as the package's
// own pages write them (config source, config section with its config member rows, config
// dns_server), and the options of config settings. Nothing here asks the router: the page
// hands the result to LuCI's uci.

export interface RuleRowValue {
  sourceId: number;
  include: string[];
  exclude: string[];
  protocols: string[];
}

export interface RuleValue {
  title: string;
  enabled: boolean;
  lists: string[];
  mode: 'servers' | 'direct' | 'block';
  // the rows that are marked, in the order of the sources
  rows: RuleRowValue[];
}

export interface DnsServerValue {
  type: string;
  server: string;
}

export interface DnsValue {
  bootstrap: string;
  servers: DnsServerValue[];
  mode: string;
  addresses: string;
  ttl: string;
}

export interface UciSection {
  type: string;
  // a row of a rule and a DNS server have no name
  name?: string;
  options: Record<string, string | string[]>;
}

export interface WizardConfig {
  // in the order they are written: the order of the rules is their priority
  sections: UciSection[];
  settings: Record<string, string>;
}

// direct and block name where a row goes without a server: no section may have these names
const RESERVED = ['direct', 'block', 'settings'];

function lines(text: string): string[] {
  return text
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean);
}

function sourceOptions(source: WizardSource): UciSection['options'] {
  const settings = source.settings;
  const options: UciSection['options'] = { type: source.kind };
  if (settings.label.trim()) options.label = settings.label.trim();
  if (settings.skipDownloads) options.skip_downloads = '1';
  if (source.kind === 'subscription') {
    options.url = source.url ?? '';
    if (settings.updateInterval && settings.updateInterval !== 'auto') {
      options.update_interval = settings.updateInterval;
    }
    const request = listRequest(
      settings.userAgent,
      lines(settings.headers),
      settings.agentPreset,
    );
    if (request.user_agent_preset) {
      options.user_agent_preset = request.user_agent_preset;
    }
    if (request.user_agent) options.user_agent = request.user_agent;
    if (request.headers?.length) options.header = request.headers;
  } else if (source.kind === 'links') {
    options.link = [...(source.links ?? [])];
    if (settings.udpOverTcp) options.udp_over_tcp = '1';
  } else if (source.kind === 'json') {
    options.outbound_json = source.json ?? '';
  } else {
    if (source.iface) options.interface = source.iface;
    if (settings.routingMark.trim()) {
      options.routing_mark = settings.routingMark.trim();
    }
    if (settings.resolver) {
      options.domain_resolver_enabled = '1';
      options.domain_resolver_dns_type = settings.dnsType;
      options.domain_resolver_dns_server = settings.dnsServer;
    }
  }
  return options;
}

// buildConfig turns what the wizard holds into the sections of the file. taken are the names
// the file has already: a new section gets the first free name of its kind (src1, rule1…).
export function buildConfig(
  sources: WizardSource[],
  rules: RuleValue[],
  dns: DnsValue,
  taken: string[] = [],
): WizardConfig {
  const used = new Set([...taken, ...RESERVED]);
  const free = (prefix: string): string => {
    for (let index = 1; ; index++) {
      const name = prefix + index;
      if (!used.has(name)) {
        used.add(name);
        return name;
      }
    }
  };
  const sections: UciSection[] = [];
  const names = new Map<number, string>();
  for (const source of sources) {
    const name = free('src');
    names.set(source.id, name);
    sections.push({ type: 'source', name, options: sourceOptions(source) });
  }
  for (const rule of rules) {
    const name = free('rule');
    const options: UciSection['options'] = {};
    if (rule.title.trim()) options.label = rule.title.trim();
    if (!rule.enabled) options.enabled = '0';
    if (rule.lists.length) options.community_lists = [...rule.lists];
    sections.push({ type: 'section', name, options });
    if (rule.mode !== 'servers') {
      // a rule that sends its sites directly or blocks them is one row with that word
      sections.push({
        type: 'member',
        options: { section: name, role: 'server', source: rule.mode },
      });
      continue;
    }
    for (const row of rule.rows) {
      const source = names.get(row.sourceId);
      if (!source) continue;
      const member: UciSection['options'] = {
        section: name,
        role: 'server',
        source,
      };
      if (row.include.length) member.include = [...row.include];
      if (row.exclude.length) member.exclude = [...row.exclude];
      if (row.protocols.length) member.protocols = [...row.protocols];
      sections.push({ type: 'member', options: member });
    }
  }
  for (const server of dns.servers) {
    const options: UciSection['options'] = { type: server.type };
    if (server.type !== 'provider') options.server = server.server.trim();
    sections.push({ type: 'dns_server', options });
  }
  return {
    sections,
    settings: {
      bootstrap_dns_server: dns.bootstrap.trim(),
      dns_mode: dns.mode,
      dns_addresses: dns.addresses,
      dns_rewrite_ttl: dns.ttl.trim(),
    },
  };
}
