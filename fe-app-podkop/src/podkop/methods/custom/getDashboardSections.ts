import { getConfigModel } from './getConfigModel';
import { Podkop } from '../../types';
import { PodkopShellMethods } from '../shell';
import { ruleExit, serverDisplayName } from '../../sources';

interface IGetDashboardSectionsResponse {
  success: boolean;
  data: Podkop.OutboundGroup[];
}

// the tile of an outbound the selector of a rule offers: the URL test of the rule first, its
// servers by the labels of their sources, the tiers of its fallbacks of several servers
function outboundName(
  code: string,
  rule: string,
  sources: Podkop.ConfigSource[],
): string {
  if (code === `${rule}-urltest-out`) return _('Fastest');
  if (code === 'block') return _('Refused: the rule has no server now');
  const tier = code.match(/^(.+)-fallback-(\d+)-out$/);
  if (tier && tier[1] === rule) return _('Fallback %s').format(tier[2]);
  return serverDisplayName(code, sources);
}

// The rules that go through servers, each as the selector "<rule>-out" of its outbounds
// (the backend's plan/exits.go): the URL test "<rule>-urltest-out", the servers of its
// rows, the URL tests "<rule>-fallback-N-out" of its fallbacks of several servers. A rule
// whose one row is direct or block has no outbound, nor has one whose sources are not
// filled yet; a disabled rule is not there.
export async function getDashboardSections(): Promise<IGetDashboardSectionsResponse> {
  const { rules, sources, members } = await getConfigModel();
  const clashProxies = await PodkopShellMethods.getClashApiProxies();

  if (!clashProxies.success) {
    return {
      success: false,
      data: [],
    };
  }

  const proxies = clashProxies.data.proxies ?? {};

  const data = rules
    .filter(
      (rule) =>
        rule.enabled !== '0' && ruleExit(rule, sources, members) === 'servers',
    )
    .map((rule) => {
      const name = rule['.name'];
      const code = `${name}-out`;
      const selector = proxies[code];
      const displayName = String(rule.label ?? '').trim() || name;

      // the running configuration does not have the rule yet
      if (!selector) {
        return { withTagSelect: false, code, displayName, outbounds: [] };
      }

      return {
        withTagSelect: true,
        code,
        displayName,
        outbounds: (selector.all ?? []).map((tag) => {
          const item = proxies[tag];
          return {
            code: tag,
            displayName: outboundName(tag, name, sources),
            latency: item?.history?.[0]?.delay || 0,
            type: item?.type || '',
            selected: selector.now === tag,
          };
        }),
      };
    });

  return {
    success: true,
    data,
  };
}
