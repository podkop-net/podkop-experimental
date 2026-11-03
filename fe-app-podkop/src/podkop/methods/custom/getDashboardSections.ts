import { getConfigModel } from './getConfigModel';
import { ClashAPI, Podkop } from '../../types';
import { PodkopShellMethods } from '../shell';
import { ruleExit } from '../../sources';
import { ruleTiles } from './ruleTiles';

interface IGetDashboardSectionsResponse {
  success: boolean;
  data: Podkop.OutboundGroup[];
}

// usedTags are the tags the connections go through by the selectors of all the rules: the choice of
// a selector and on down the choices under it, to the end (a URL test may have chosen the URL test
// of a fallback). Rules that take one source have the same tags, and their tests may choose
// differently. A tag seen before has had the rest of its way walked.
export function usedTags(
  proxies: ClashAPI.Proxies['proxies'],
  selectors: string[],
): Set<string> {
  const used = new Set<string>();
  selectors.forEach((selector) => {
    let tag = proxies[selector]?.now;
    while (tag && !used.has(tag)) {
      used.add(tag);
      tag = proxies[tag]?.now;
    }
  });
  return used;
}

// getUsedTags reads usedTags anew: a URL test may have switched since the grid was drawn. undefined
// when the Clash API does not answer.
export async function getUsedTags(
  selectors: string[],
): Promise<Set<string> | undefined> {
  const clashProxies = await PodkopShellMethods.getClashApiProxies();
  const proxies = clashProxies.success ? clashProxies.data.proxies : undefined;
  return proxies ? usedTags(proxies, selectors) : undefined;
}

// The rules that go through servers, each as the selector "<rule>-out" of its outbounds
// (the backend's plan/exits.go): the URL test "<rule>-urltest-out" and all the servers of its
// rows, those of its fallbacks too, laid out by ruleTiles. A rule whose one row is direct or
// block has no outbound, nor has one whose sources are not filled yet; a disabled rule is not
// there.
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

  const running = rules.filter(
    (rule) =>
      rule.enabled !== '0' && ruleExit(rule, sources, members) === 'servers',
  );
  const used = usedTags(
    proxies,
    running.map((rule) => `${rule['.name']}-out`),
  );

  const data = running.map((rule) => {
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
      ...ruleTiles(proxies, name, sources, members, used),
    };
  });

  return {
    success: true,
    data,
  };
}
