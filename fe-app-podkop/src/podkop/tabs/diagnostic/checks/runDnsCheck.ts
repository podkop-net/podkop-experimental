import { insertIf } from '../../../../helpers';
import { DIAGNOSTICS_CHECKS_MAP } from './contstants';
import { PodkopShellMethods } from '../../../methods';
import { IDiagnosticsChecksItem } from '../../../services';
import { Podkop } from '../../../types';
import { updateCheckStore } from './updateCheckStore';
import { getMeta } from '../helpers/getMeta';

// the name of a server of the list: its address and type, or the provider's servers
function serverName(server: Podkop.DnsCheckServer): string {
  if (server.type !== 'provider') return `${server.server} [${server.type}]`;
  return server.providers?.length
    ? _("The provider's DNS: %s").format(server.providers.join(', '))
    : _("The provider's DNS: the router knows none now");
}

// a server that replies with a refusal is there, but each query skips it: a warning
function serverItem(
  server: Podkop.DnsCheckServer,
  key: string,
): IDiagnosticsChecksItem {
  if (server.status)
    return { state: 'success', key, value: serverName(server) };
  if (!server.refusal)
    return { state: 'error', key, value: serverName(server) };
  return {
    state: 'warning',
    key,
    value: `${serverName(server)} — ${_('replies %s').format(server.refusal)}`,
  };
}

// The line of the one server as before the list, or a line of each server in its order, the
// first telling how they are asked.
export function dnsServerItems(
  servers: Podkop.DnsCheckServer[],
  mode: string | undefined,
): IDiagnosticsChecksItem[] {
  if (servers.length === 1) {
    return [serverItem(servers[0], _('Main DNS'))];
  }
  const asked =
    mode === 'fastest' ? _('the fastest first') : _('in their order');
  return servers.map((server, index) =>
    serverItem(
      server,
      index === 0
        ? _('DNS %d of %d, %s').format(index + 1, servers.length, asked)
        : _('DNS %d').format(index + 1),
    ),
  );
}

export async function runDnsCheck() {
  const { order, title, code } = DIAGNOSTICS_CHECKS_MAP.DNS;

  updateCheckStore({
    order,
    code,
    title,
    description: _('Checking, please wait'),
    state: 'loading',
    items: [],
  });

  const dnsChecks = await PodkopShellMethods.checkDNSAvailable();

  if (!dnsChecks.success) {
    updateCheckStore({
      order,
      code,
      title,
      description: _('Cannot receive checks result'),
      state: 'error',
      items: [],
    });

    throw new Error('DNS checks failed');
  }

  const data = dnsChecks.data;
  const servers: Podkop.DnsCheckServer[] = data.dns_servers?.length
    ? data.dns_servers
    : [
        {
          type: data.dns_type,
          server: data.dns_server,
          status: data.dns_status,
        },
      ];

  // a server of the list that does not answer leaves the others: a warning
  const allGood =
    Boolean(data.dns_on_router) &&
    Boolean(data.dhcp_config_status) &&
    Boolean(data.bootstrap_dns_status) &&
    servers.every((server) => Boolean(server.status));

  const atLeastOneGood =
    Boolean(data.dns_on_router) ||
    Boolean(data.dhcp_config_status) ||
    Boolean(data.bootstrap_dns_status) ||
    Boolean(data.dns_status);

  const { state, description } = getMeta({ atLeastOneGood, allGood });

  updateCheckStore({
    order,
    code,
    title,
    description,
    state,
    items: [
      ...insertIf<IDiagnosticsChecksItem>(
        servers.some(
          (server) => server.type === 'doh' || server.type === 'dot',
        ) || !data.bootstrap_dns_status,
        [
          {
            state: data.bootstrap_dns_status ? 'success' : 'error',
            key: _('Bootsrap DNS'),
            value: data.bootstrap_dns_server,
          },
        ],
      ),
      ...dnsServerItems(servers, data.dns_mode),
      {
        state: data.dns_on_router ? 'success' : 'error',
        key: _('DNS on router'),
        value: '',
      },
      {
        state: data.dhcp_config_status ? 'success' : 'error',
        key: _('DHCP has DNS server'),
        value: '',
      },
    ],
  });

  if (!atLeastOneGood) {
    throw new Error('DNS checks failed');
  }
}
