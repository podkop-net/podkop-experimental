import { DIAGNOSTICS_CHECKS_MAP } from './contstants';
import { PodkopShellMethods } from '../../../methods';
import { updateCheckStore } from './updateCheckStore';
import { getMeta } from '../helpers/getMeta';
import { getDashboardSections } from '../../../methods/custom/getDashboardSections';
import { IDiagnosticsChecksItem } from '../../../services';
import { ClashAPI, Podkop } from '../../../types';
import { getConfigModel } from '../../../methods/custom/getConfigModel';
import { serverDisplayName } from '../../../sources';

type Latency = Pick<IDiagnosticsChecksItem, 'state' | 'value' | 'servers'>;

function responded(answer: {
  success: boolean;
  data: Podkop.GetClashApiProxyLatency;
}): number {
  return answer.success && !answer.data.message ? answer.data.delay : 0;
}

// What a URL test none of whose servers gives a delay goes through now: a fallback of the rule,
// or nothing. A server that was chosen before the test is tested again here too.
async function chosenLatency(
  section: Podkop.OutboundGroup,
  test: Podkop.Outbound,
  proxies: Record<string, ClashAPI.ProxyBase>,
  servers: Latency['servers'],
): Promise<Latency> {
  const now = proxies[test.code]?.now;

  if (!now || now === 'block') {
    return {
      state: 'error',
      value: `[${test.displayName}] ${_('Not responding')}`,
      servers,
    };
  }

  // the selector of the rule offers every server and tier the URL test may take but direct
  const offered = section.outbounds.find((item) => item.code === now);
  const name =
    now === 'direct-out' ? _('Directly') : (offered?.displayName ?? now);
  // a fallback: direct, or a URL test of several servers
  const fallback = now === 'direct-out' || proxies[now]?.type === 'URLTest';
  const delay = responded(
    await PodkopShellMethods.getClashApiProxyLatency(now),
  );

  if (!delay) {
    return {
      state: 'error',
      value: `[${test.displayName} → ${name}] ${_('Not responding')}`,
      servers,
    };
  }

  return {
    state: fallback ? 'warning' : 'success',
    value: `[${test.displayName} → ${name}] ${delay}ms`,
    servers,
  };
}

// What the selector of a rule has chosen is tested: the URL test of the rule with its own
// servers, the one server of the rule, or what is pinned on the dashboard. A test of the
// selector would test every server of every fallback with them.
async function ruleLatency(
  section: Podkop.OutboundGroup,
  sources: Podkop.ConfigSource[],
): Promise<Latency> {
  const selected = section.outbounds.find((item) => item.selected);

  if (!selected) {
    return { state: 'error', value: _('Not responding') };
  }

  if (selected.type !== 'URLTest') {
    const delay = responded(
      await PodkopShellMethods.getClashApiProxyLatency(selected.code),
    );

    return delay
      ? { state: 'success', value: `[${selected.displayName}] ${delay}ms` }
      : {
          state: 'error',
          value: `[${selected.displayName}] ${_('Not responding')}`,
        };
  }

  const latencyGroup = await PodkopShellMethods.getClashApiGroupLatency(
    selected.code,
  );
  const answered =
    latencyGroup.success && !latencyGroup.data.message ? latencyGroup.data : {};
  const listed = await PodkopShellMethods.getClashApiProxies();
  const proxies = listed.success ? (listed.data.proxies ?? {}) : {};
  const test = proxies[selected.code];
  const members = (test?.all ?? Object.keys(answered)).slice(
    0,
    (test?.all?.length ?? Object.keys(answered).length) -
      (test?.fallbacks?.length ?? 0),
  );
  // sing-box answers the delays of the servers that answered. It answers nothing while a round
  // of the test is under way, and a long round is cut by the timeout: the server keeps the delay
  // of its last test then, and a server that failed its last test has none.
  const servers = members
    .map((tag) => ({
      name: serverDisplayName(tag, sources),
      delay: answered[tag] || proxies[tag]?.history?.[0]?.delay || 0,
    }))
    .sort(
      (left, right) =>
        (left.delay || Infinity) - (right.delay || Infinity) ||
        left.name.localeCompare(right.name),
    );
  const answering = servers.filter((server) => server.delay).length;

  if (!answering) {
    return chosenLatency(section, selected, proxies, servers);
  }

  return {
    state: 'success',
    value: `[${selected.displayName}] ${_('%s of %s answer').format(answering, servers.length)}`,
    servers,
  };
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

  const { sources } = await getConfigModel();

  const items = (await Promise.all(
    sections.data.map(async (section) => {
      async function getLatency(): Promise<Latency> {
        if (section.withTagSelect) {
          return ruleLatency(section, sources);
        }

        const delay = responded(
          await PodkopShellMethods.getClashApiProxyLatency(section.code),
        );

        return delay
          ? { state: 'success', value: `${delay} ms` }
          : { state: 'error', value: _('Not responding') };
      }

      return { key: section.displayName, ...(await getLatency()) };
    }),
  )) as Array<IDiagnosticsChecksItem>;

  // what goes without a proxy, through the WAN of the router: tested the same way
  const direct = await PodkopShellMethods.getClashApiProxyLatency('direct-out');
  const directWorks = direct.success && !direct.data.message;
  items.push({
    state: directWorks ? 'success' : 'error',
    key: _('Direct (without a proxy)'),
    value: directWorks ? `${direct.data.delay} ms` : _('Not responding'),
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
