import { DIAGNOSTICS_CHECKS_MAP } from './contstants';
import { PodkopShellMethods } from '../../../methods';
import { updateCheckStore } from './updateCheckStore';
import { getMeta } from '../helpers/getMeta';
import { getDashboardSections } from '../../../methods/custom/getDashboardSections';
import { routeLabel, ruleTiles } from '../../../methods/custom/ruleTiles';
import { IDiagnosticsChecksItem } from '../../../services';
import { Podkop } from '../../../types';
import { getConfigModel } from '../../../methods/custom/getConfigModel';

type Latency = Pick<IDiagnosticsChecksItem, 'state' | 'value'>;

function responded(answer: {
  success: boolean;
  data: Podkop.GetClashApiProxyLatency;
}): number {
  return answer.success && !answer.data.message ? answer.data.delay : 0;
}

// measure tests an outbound once a run, however many rules go through it, the direct one too
type Measure = (tag: string) => Promise<number>;

function oncePerTag(): Measure {
  const runs = new Map<string, Promise<number>>();
  return (tag) => {
    let run = runs.get(tag);
    if (!run) {
      run = PodkopShellMethods.getClashApiProxyLatency(tag).then(responded);
      runs.set(tag, run);
    }
    return run;
  };
}

// The line of a rule: how it chose where its connections go and that server's answer, as
// "Fastest: EE 158 ms", "Fastest → Fallback 2: LV 120 ms", "Manual: DE — Not responding" or,
// for a rule of one server, "RU 80 ms". A fallback in use is a warning: the servers of the rule
// do not answer.
async function routeLatency(
  route: Podkop.OutboundRoute,
  measure: Measure,
): Promise<Latency> {
  const label = routeLabel(route);
  const name = label ? `${label}: ${route.displayName}` : route.displayName;
  if (route.code === 'block') {
    // the block of a rule whose sources name no server now names itself
    return {
      state: 'error',
      value: label
        ? `${label}: ${_('connections are refused')}`
        : route.displayName,
    };
  }
  const delay = await measure(route.code);
  if (!delay) {
    return { state: 'error', value: `${name} — ${_('Not responding')}` };
  }
  return {
    state: route.mode === 'auto' && route.tier ? 'warning' : 'success',
    value: `${name} ${delay} ms`,
  };
}

// how often and how long what a rule goes through is read again after its server failed
const REREAD_MS = 300;
const REREADS = 4;

// Only the server each rule goes through now is tested, not its URL test: a group test waits for
// the slowest of the servers, and a dead one holds it to the deadline. The URL test of the rule
// tests its servers itself. A chosen server that does not answer has its failure stored by the
// test, and sing-box then has the URL test choose again, just after it answered the test: what
// the rule goes through is read again for a moment, and a new choice is tested in its turn, alone.
async function ruleLatency(
  section: Podkop.OutboundGroup,
  measure: Measure,
  model: Podkop.ConfigModel,
): Promise<Latency> {
  if (!section.route) {
    return { state: 'error', value: _('Not responding') };
  }
  const line = await routeLatency(section.route, measure);
  if (line.state !== 'error' || section.route.mode !== 'auto') return line;
  for (let read = 0; read < REREADS; read++) {
    if (read) await new Promise((done) => setTimeout(done, REREAD_MS));
    const listed = await PodkopShellMethods.getClashApiProxies();
    if (!listed.success) return line;
    const { route } = ruleTiles(
      listed.data.proxies ?? {},
      section.rule ?? section.code.replace(/-out$/, ''),
      model.sources,
      model.members,
      new Set(),
      listed.data.podkop_tags,
    );
    if (route && route.code !== section.route.code) {
      return routeLatency(route, measure);
    }
  }
  return line;
}

export async function runSectionsCheck() {
  const { order, title, code } = DIAGNOSTICS_CHECKS_MAP.OUTBOUNDS;

  updateCheckStore({
    order,
    code,
    title,
    description: _('Checking, please wait'),
    state: 'loading',
    items: [],
  });

  const sections = await getDashboardSections();

  if (!sections.success) {
    updateCheckStore({
      order,
      code,
      title,
      description: _('Cannot receive checks result'),
      state: 'error',
      items: [],
    });

    throw new Error('Sections checks failed');
  }

  const model = await getConfigModel();
  const measure = oncePerTag();
  // what goes without a proxy, through the WAN of the router: tested the same way, at once
  const direct = measure('direct-out');

  const items = (await Promise.all(
    sections.data.map(async (section) => {
      async function getLatency(): Promise<Latency> {
        if (section.withTagSelect) {
          return ruleLatency(section, measure, model);
        }

        const delay = await measure(section.code);

        return delay
          ? { state: 'success', value: `${delay} ms` }
          : { state: 'error', value: _('Not responding') };
      }

      return { key: section.displayName, ...(await getLatency()) };
    }),
  )) as Array<IDiagnosticsChecksItem>;

  const directDelay = await direct;
  items.push({
    state: directDelay ? 'success' : 'error',
    key: _('Direct (without a proxy)'),
    value: directDelay ? `${directDelay} ms` : _('Not responding'),
  });

  const allGood = items.every((item) => item.state === 'success');

  // a rule that goes through a fallback works
  const atLeastOneGood = items.some((item) => item.state !== 'error');

  const { state, description } = getMeta({ atLeastOneGood, allGood });

  updateCheckStore({
    order,
    code,
    title,
    description,
    state,
    items,
  });

  if (!atLeastOneGood) {
    throw new Error('Sections checks failed');
  }
}
