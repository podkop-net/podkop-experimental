import { detectPasted, linkName } from '../sources';
import { presetName } from '../../validators/validateRequestHeader';
import type { Podkop } from '../types';

// The settings of a source, by the options of the package's settings (config source): the
// wizard writes nothing else. A paste makes a source with the defaults; the manual form sets them.
export interface SourceSettings {
  label: string;
  skipDownloads: boolean;
  // subscription
  updateInterval: string;
  agentPreset: string;
  userAgent: string;
  headers: string;
  // links
  udpOverTcp: boolean;
  // interface
  routingMark: string;
  resolver: boolean;
  dnsType: string;
  dnsServer: string;
}

export function defaultSettings(): SourceSettings {
  return {
    label: '',
    skipDownloads: false,
    updateInterval: 'auto',
    agentPreset: 'podkop',
    userAgent: '',
    headers: '',
    udpOverTcp: false,
    routingMark: '',
    resolver: false,
    dnsType: 'udp',
    dnsServer: '1.1.1.1',
  };
}

export type SourceKind = 'subscription' | 'links' | 'json' | 'interface';

// A source the wizard holds until the settings are written: one paste makes one source, as a
// source of the page is made (a subscription, the links of servers, an outbound JSON).
export interface WizardSource {
  id: number;
  kind: SourceKind;
  url?: string;
  links?: string[];
  json?: string;
  iface?: string;
  settings: SourceSettings;
  // what the router told of a subscription when its list was loaded
  provider?: string;
  servers?: number;
  // the servers of the list as they came, those the engine does not read with the reason
  list?: ListedServer[];
}

export interface ListedServer {
  name: string;
  scheme: string;
  address: string;
  reason: string;
}

export function listedServers(
  preview: Podkop.SubscriptionPreview | null,
): ListedServer[] {
  return (preview?.servers ?? []).map((item) => ({
    name: item.name,
    scheme: item.scheme,
    address: item.address ?? '',
    reason: item.reason ?? '',
  }));
}

export type NewSource = Omit<WizardSource, 'id'>;

export function hostOf(address: string): string {
  try {
    return new URL(address).hostname;
  } catch (_e) {
    return address;
  }
}

// how a source shows in the list: its name, and a line of what it is
export function describe(source: NewSource): {
  title: string;
  subtitle: string;
} {
  const label = source.settings.label.trim();
  switch (source.kind) {
    case 'subscription': {
      const host = hostOf(source.url ?? '');
      const parts = ['Подписка', host];
      if (source.servers) parts.push(serversText(source.servers));
      if (source.settings.agentPreset !== 'podkop') {
        parts.push(
          'запрашивается как ' + presetName(source.settings.agentPreset),
        );
      }
      return {
        title: label || source.provider || host,
        subtitle: parts.join(' · '),
      };
    }
    case 'links': {
      const links = source.links ?? [];
      const names = links.map(
        (link, index) => linkName(link) || 'сервер ' + (index + 1),
      );
      const parts = [serversText(links.length), names.join(', ')];
      if (source.settings.udpOverTcp) parts.push('UDP через TCP');
      return {
        title: label || 'Ссылки на серверы',
        subtitle: parts.join(' · '),
      };
    }
    case 'json': {
      const found = detectPasted(source.json ?? '');
      return {
        title: label || 'Outbound JSON',
        subtitle: found.title.replace(/^[^:]*:\s*/, ''),
      };
    }
    case 'interface': {
      const name = source.iface || 'основной маршрут';
      const parts = ['Интерфейс', name];
      if (source.settings.resolver) {
        parts.push('резолвер ' + source.settings.dnsServer);
      }
      return { title: label || name, subtitle: parts.join(' · ') };
    }
  }
}

// What the field answers a paste with: a line under it, and the source it made, if any.
export interface ImportOutcome {
  tone: 'ok' | 'warn' | 'bad';
  title: string;
  detail?: string;
  source?: NewSource;
  // the subscription whose list had no servers: the alert offers to set it up, with what came
  setup?: { url: string; preview: Podkop.SubscriptionPreview | null };
}

// what the importer asks the router: injected, so that the logic is tested without one
export interface ImportDeps {
  checkLinks(links: string[]): Promise<Podkop.LinkCheck[] | null>;
  loadSubscription(
    url: string,
    request?: Podkop.ListRequest,
    // a load that is no longer wanted: its job on the router is cancelled
    control?: { cancelled: boolean },
  ): Promise<Podkop.SubscriptionPreview | null>;
}

// the head of a pasted text, to name what was not taken without showing a secret whole
export function head(text: string): string {
  const line = text.trim().split(/\s+/)[0] ?? '';
  const scheme = line.includes('://')
    ? line.slice(0, line.indexOf('://') + 3)
    : line.slice(0, 16);
  return scheme + '…';
}

function unsupported(text: string): ImportOutcome {
  return {
    tone: 'bad',
    title: 'Неподдерживаемая ссылка',
    detail: head(text) + ' не импортирована.',
  };
}

function plural(count: number, one: string, few: string, many: string) {
  const tens = count % 100;
  const units = count % 10;
  if (tens > 10 && tens < 20) return many;
  if (units === 1) return one;
  if (units > 1 && units < 5) return few;
  return many;
}

export function serversText(count: number): string {
  return count + ' ' + plural(count, 'сервер', 'сервера', 'серверов');
}

// importPasted tells what a pasted text becomes: a source of the list, or why none
export async function importPasted(
  text: string,
  existing: WizardSource[],
  deps: ImportDeps,
): Promise<ImportOutcome | null> {
  const found = detectPasted(text);
  if (!found.kind) return null;
  if (found.kind === 'error') return unsupported(text);

  if (found.kind === 'subscription') {
    const url = String(found.url ?? '');
    const host = hostOf(url);
    if (existing.some((item) => item.url === url)) {
      return { tone: 'warn', title: 'Уже добавлено', detail: host };
    }
    const preview = await deps.loadSubscription(url);
    const servers = (preview?.servers ?? []).filter((item) => !item.reason);
    if (!servers.length) {
      return {
        tone: 'bad',
        title: 'Не удалось получить подписку',
        detail: host,
        setup: { url, preview },
      };
    }
    const source: NewSource = {
      kind: 'subscription',
      url,
      settings: defaultSettings(),
      provider: preview?.provider?.title?.trim() || '',
      servers: servers.length,
      list: listedServers(preview),
    };
    return {
      tone: 'ok',
      title: 'Импортирована подписка',
      detail: describe(source).title + ' · ' + serversText(servers.length),
      source,
    };
  }

  if (found.kind === 'json') {
    const json = String(found.json ?? '');
    if (existing.some((item) => item.json === json)) {
      return { tone: 'warn', title: 'Уже добавлено', detail: found.title };
    }
    return {
      tone: 'ok',
      title: 'Импортирован outbound JSON',
      source: { kind: 'json', json, settings: defaultSettings() },
    };
  }

  // links of servers: the router tells which of them its engine reads
  const links = found.links ?? [];
  const checks = await deps.checkLinks(links);
  const good = links.filter((_link, index) => !checks || checks[index]?.ok);
  if (!good.length) return unsupported(text);
  const known = new Set(existing.flatMap((item) => item.links ?? []));
  const fresh = good.filter((link) => !known.has(link));
  if (!fresh.length) {
    return {
      tone: 'warn',
      title: 'Уже добавлено',
      detail: good.map((link) => linkName(link) || head(link)).join(', '),
    };
  }
  const names = fresh.map(
    (link, index) => linkName(link) || 'сервер ' + (index + 1),
  );
  const source: NewSource = {
    kind: 'links',
    links: fresh,
    settings: defaultSettings(),
  };
  if (good.length < links.length) {
    const skipped = links
      .map((_link, index) => index)
      .filter((index) => checks && !checks[index]?.ok)
      .map((index) => index + 1);
    return {
      tone: 'warn',
      title: 'Импортировано ' + good.length + ' из ' + links.length,
      detail:
        (skipped.length === 1 ? 'Строка ' : 'Строки ') +
        skipped.join(', ') +
        (skipped.length === 1 ? ' пропущена.' : ' пропущены.'),
      source,
    };
  }
  return {
    tone: 'ok',
    title:
      fresh.length === 1
        ? 'Импортирована ссылка на сервер'
        : 'Импортированы ссылки на серверы: ' + fresh.length,
    detail: names.join(', '),
    source,
  };
}
