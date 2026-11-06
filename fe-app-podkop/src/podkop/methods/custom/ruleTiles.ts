import { ClashAPI, Podkop } from '../../types';
import { serverDisplayName, sourceLabel } from '../../sources';

// The layout of the tiles of a rule on the dashboard and the line of the outbounds check, from
// the Clash API alone: no import here reaches the services of the page.

// the outbounds of a rule: those the backend tells (Podkop.Tags), or those of the tags a backend
// that does not tell makes of the section
export function ruleOutbounds(
  rule: string,
  tags?: Podkop.Tags,
): { selector: string; test: string } {
  const told = tags?.rules?.[rule];
  if (told) return { selector: told.selector, test: told.test ?? '' };
  return { selector: `${rule}-out`, test: `${rule}-urltest-out` };
}

// the fallback row (from 1) of the rule whose URL test the tag is; 0 for another
function fallbackRow(tag: string, rule: string, tags?: Podkop.Tags): number {
  if (tags?.outbounds) {
    const what = tags.outbounds[tag];
    return what?.rule === rule ? (what.fallback ?? 0) : 0;
  }
  const group = tag.match(/^(.+)-fallback-(\d+)-out$/);
  return group && group[1] === rule ? Number(group[2]) : 0;
}

// the name of a tile: a server by the labels of its sources; a URL test of the rule and the block
// of a rule whose sources name no server now by what they do
function outboundName(
  code: string,
  rule: string,
  sources: Podkop.ConfigSource[],
  tags?: Podkop.Tags,
): string {
  if (code === ruleOutbounds(rule, tags).test) return _('Fastest');
  if (code === 'block') return _('Refused: the rule has no server now');
  const row = fallbackRow(code, rule, tags);
  if (row) return _('Fallback %s').format(row);
  return serverDisplayName(code, sources, tags);
}

const DIRECT_TAG = 'direct-out';
const BLOCK_TAG = 'block';

// the name of the nth fallback tier, with the label of the source of a fallback of several servers:
// its URL test is that of a fallback row of the rule
function tierName(
  place: number,
  tag: string,
  rule: string,
  sources: Podkop.ConfigSource[],
  members: Podkop.ConfigMember[],
  tags?: Podkop.Tags,
): string {
  const name = _('Fallback %s').format(place);
  const number = fallbackRow(tag, rule, tags);
  if (!number) return name;
  const row = members.filter(
    (item) => item.section === rule && item.role === 'fallback',
  )[number - 1];
  const source = sources.find((item) => item['.name'] === row?.source);
  return source ? `${name} · ${sourceLabel(source)}` : name;
}

// LOSS_MIN_SEGMENTS is what the engine decides by: the shortest window with about a megabyte of
// probes (urltest lossMinSegments)
const LOSS_MIN_SEGMENTS = 700;

// lossOf tells the loss the probes of a server counted: the shortest window with enough
// segments, as the engine weighs it, and every window for the title
export function lossOf(loss?: ClashAPI.ProxyLoss): {
  text?: string;
  title?: string;
} {
  const windows = loss?.windows ?? [];
  const rate = (lost: number, segments: number) =>
    `${((lost * 100) / segments).toFixed(1)}%`;
  const decided = windows.find((item) => item.segments >= LOSS_MIN_SEGMENTS);
  const lines = windows
    .filter((item) => item.segments > 0)
    .map(
      (item) =>
        `${_('%dh').format(item.hours)}: ${rate(item.lost, item.segments)} (${_('%d probes').format(item.probes)})`,
    );
  if (loss?.not_counted) lines.push(_('The last probe could not count'));
  return {
    text: decided ? rate(decided.lost, decided.segments) : undefined,
    title: lines.length ? `${_('Loss')}: ${lines.join(', ')}` : undefined,
  };
}

// ruleTiles lays out the tiles of a rule in the order its connections take them (podkop-engine
// urltest.fallbacks): the servers of its URL test, of which the fastest is taken, then each
// fallback, taken only while nothing before it answers. A fallback of several servers is a URL
// test of its own and shows its servers; direct and block as a fallback show as tiles the
// selector does not offer. route is where the connections go: the choice of the URL test, on
// down through the URL test of a fallback, or a server pinned on the dashboard. used is what the
// connections of all the rules go through (usedTags). tags are what the outbounds are, as the
// backend tells (Podkop.Tags).
export function ruleTiles(
  proxies: ClashAPI.Proxies['proxies'],
  rule: string,
  sources: Podkop.ConfigSource[],
  members: Podkop.ConfigMember[],
  used: Set<string>,
  tags?: Podkop.Tags,
): Required<Pick<Podkop.OutboundGroup, 'outbounds' | 'tiers'>> &
  Pick<Podkop.OutboundGroup, 'auto' | 'route'> {
  const ruleTags = ruleOutbounds(rule, tags);
  const selector = proxies[ruleTags.selector];
  const offered = selector?.all ?? [];
  const autoTag = ruleTags.test;
  const test =
    autoTag && offered.includes(autoTag) ? proxies[autoTag] : undefined;
  const balance = new Map(
    (test?.balance ?? []).map((item) => [item.name, item.devices]),
  );
  const tile = (tag: string, tier: number): Podkop.Outbound => {
    const item = proxies[tag];
    let displayName = outboundName(tag, rule, sources, tags);
    if (tag === DIRECT_TAG) displayName = _('Directly');
    else if (tag === BLOCK_TAG && tier > 0) displayName = _('Block');
    const loss = lossOf(item?.loss);
    const balanced = tier === 0 ? balance.get(tag) : undefined;
    return {
      loss: loss.text,
      lossTitle: loss.title,
      balanced: balanced !== undefined,
      devices: balanced,
      code: tag,
      displayName,
      latency: item?.history?.[0]?.delay || 0,
      type: item?.type || '',
      selected: selector?.now === tag,
      inUse: used.has(tag),
      active: false,
      pick: false,
      tier,
      selectable: offered.includes(tag),
    };
  };

  if (!test) {
    // one server, or the block of a rule whose sources name none now: nothing to choose from
    const outbounds = offered.map((tag) => tile(tag, 0));
    const chosen = outbounds.find((item) => item.selected);
    if (!chosen) return { outbounds, tiers: [] };
    chosen.active = true;
    const { code, displayName, latency } = chosen;
    return {
      outbounds,
      tiers: [],
      route: { mode: 'single', tier: 0, code, displayName, latency },
    };
  }

  // without the list of the URL test (an engine before urltest.fallbacks) the selector tells its
  // servers, and its fallbacks are not known
  const fallbacks = test.all ? (test.fallbacks ?? []) : [];
  const servers = test.all
    ? test.all.slice(0, test.all.length - fallbacks.length)
    : offered.filter((tag) => tag !== autoTag);
  const outbounds = servers.map((tag) => tile(tag, 0));
  const groups = new Map<number, string>();
  fallbacks.forEach((tag, index) => {
    const group = proxies[tag];
    if (group?.type === 'URLTest') {
      groups.set(index + 1, tag);
      (group.all ?? []).forEach((server) =>
        outbounds.push(tile(server, index + 1)),
      );
    } else {
      outbounds.push(tile(tag, index + 1));
    }
  });
  // what the selector offers beyond them stays in view with the servers
  const placed = new Set([
    autoTag,
    ...fallbacks,
    ...outbounds.map((item) => item.code),
  ]);
  const rest = offered.filter((tag) => !placed.has(tag));
  outbounds.splice(servers.length, 0, ...rest.map((tag) => tile(tag, 0)));
  const tiers = fallbacks.length
    ? [
        _('Fastest'),
        ...fallbacks.map((tag, index) =>
          tierName(index + 1, tag, rule, sources, members, tags),
        ),
      ]
    : [];

  let active: Podkop.Outbound | undefined;
  let mode: Podkop.OutboundRoute['mode'] = 'auto';
  if (selector?.now === autoTag) {
    const chosen = test.now ?? '';
    const tier = fallbacks.indexOf(chosen) + 1;
    const leaf = groups.has(tier) ? proxies[chosen]?.now : chosen;
    active = outbounds.find((item) => item.code === leaf && item.tier === tier);
  } else if (selector?.now) {
    mode = 'manual';
    active = outbounds.find((item) => item.code === selector.now);
  }
  groups.forEach((tag, tier) => {
    const pick = outbounds.find(
      (item) => item.code === proxies[tag]?.now && item.tier === tier,
    );
    if (pick && pick !== active) pick.pick = true;
  });
  if (!active) return { outbounds, tiers, auto: autoTag };
  active.active = true;
  const { code, displayName, latency, tier = 0 } = active;
  const route: Podkop.OutboundRoute = {
    mode,
    tier,
    code,
    displayName,
    latency,
  };
  if (mode === 'auto' && (test.mode === 'loss' || test.mode === 'balance')) {
    route.choice = test.mode;
  }
  if (mode === 'auto' && !tier && balance.size) {
    route.balance = outbounds
      .filter((item) => item.balanced)
      .map((item) => item.displayName);
  }
  return { outbounds, tiers, auto: autoTag, route };
}

// routeLabel names how a rule chose where its connections go: "Fastest", "Fastest → Fallback 2",
// "Manual"; nothing for a rule of one server
export function routeLabel(route: Podkop.OutboundRoute): string {
  if (route.mode === 'single') return '';
  if (route.mode === 'manual') return _('Manual');
  let first = _('Fastest');
  if (route.choice === 'loss') first = _('Fastest, avoiding loss');
  if (route.choice === 'balance') first = _('Balance');
  return route.tier
    ? `${first} → ${_('Fallback %s').format(route.tier)}`
    : first;
}
