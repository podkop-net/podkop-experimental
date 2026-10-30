import { DIAGNOSTICS_CHECKS_MAP } from './contstants';
import { PodkopShellMethods } from '../../../methods';
import { updateCheckStore } from './updateCheckStore';
import { getMeta } from '../helpers/getMeta';
import { getDashboardSections } from '../../../methods/custom/getDashboardSections';
import { IDiagnosticsChecksItem } from '../../../services';
import { Podkop } from '../../../types';

type Latency = Pick<IDiagnosticsChecksItem, 'state' | 'value'>;

function responded(answer: {
  success: boolean;
  data: Podkop.GetClashApiProxyLatency;
}): number {
  return answer.success && !answer.data.message ? answer.data.delay : 0;
}

// What a URL test whose servers gave no delay goes through now: a server of it, a fallback of
// the rule, or nothing. sing-box answers no delay while a round of the test is under way too.
async function chosenLatency(
  section: Podkop.OutboundGroup,
  test: Podkop.Outbound,
): Promise<Latency> {
  const notResponding: Latency = {
    state: 'error',
    value: `[${test.displayName}] ${_('Not responding')}`,
  };
  const listed = await PodkopShellMethods.getClashApiProxies();
  const proxies = listed.success ? (listed.data.proxies ?? {}) : {};
  const now = proxies[test.code]?.now;

  if (!now || now === 'block') {
    return notResponding;
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
    };
  }

  return {
    state: fallback ? 'warning' : 'success',
    value: `[${test.displayName} → ${name}] ${delay}ms`,
  };
}

// What the selector of a rule has chosen is tested: the URL test of the rule with its own
// servers, or what is pinned on the dashboard. A test of the selector would test every server
// of every fallback with them.
async function ruleLatency(section: Podkop.OutboundGroup): Promise<Latency> {
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
  // the delays of the servers that answered, the fastest first
  const delays =
    latencyGroup.success && !latencyGroup.data.message
      ? Object.values(latencyGroup.data)
          .filter((item) => typeof item === 'number' && item > 0)
          .sort((left, right) => left - right)
      : [];

  if (!delays.length) {
    return chosenLatency(section, selected);
  }

  return {
    state: 'success',
    value: `[${selected.displayName}] ${delays.map((item) => `${item}ms`).join(' / ')}`,
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

  const items = (await Promise.all(
    sections.data.map(async (section) => {
      async function getLatency(): Promise<Latency> {
        if (section.withTagSelect) {
          return ruleLatency(section);
        }

        const delay = responded(
          await PodkopShellMethods.getClashApiProxyLatency(section.code),
        );

        return delay
          ? { state: 'success', value: `${delay} ms` }
          : { state: 'error', value: _('Not responding') };
      }

      const { state, value } = await getLatency();

      return {
        state,
        key: section.displayName,
        value,
      };
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
