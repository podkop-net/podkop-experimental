import { DIAGNOSTICS_CHECKS_MAP } from './contstants';
import { PodkopShellMethods } from '../../../methods';
import { updateCheckStore } from './updateCheckStore';
import { getMeta } from '../helpers/getMeta';
import { getDashboardSections } from '../../../methods/custom/getDashboardSections';
import { IDiagnosticsChecksItem } from '../../../services';

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
      async function getLatency() {
        if (section.withTagSelect) {
          const latencyGroup = await PodkopShellMethods.getClashApiGroupLatency(
            section.code,
          );

          const selectedOutbound = section.outbounds.find(
            (item) => item.selected,
          );

          // the URL test of the rule, or a tier of its fallbacks pinned on the dashboard
          const isUrlTest = selectedOutbound?.type === 'URLTest';
          const urlTestName = selectedOutbound?.displayName || _('Fastest');

          const success = latencyGroup.success && !latencyGroup.data.message;

          if (success) {
            if (isUrlTest) {
              // sing-box answers the delays of the outbounds that answered: an empty
              // answer is a group none of whose outbounds works
              const delays = Object.values(latencyGroup.data).filter(
                (item) => typeof item === 'number' && item > 0,
              );

              if (!delays.length) {
                return {
                  success: false,
                  latency: `[${urlTestName}] ${_('Not responding')}`,
                };
              }

              return {
                success: true,
                latency: `[${urlTestName}] ${delays.map((item) => `${item}ms`).join(' / ')}`,
              };
            }

            const selectedProxyDelay =
              latencyGroup.data?.[selectedOutbound?.code ?? ''];

            if (selectedProxyDelay) {
              return {
                success: true,
                latency: `[${selectedOutbound?.displayName ?? ''}] ${selectedProxyDelay}ms`,
              };
            }

            return {
              success: false,
              latency: `[${selectedOutbound?.displayName ?? ''}] ${_('Not responding')}`,
            };
          }

          return {
            success: false,
            latency: _('Not responding'),
          };
        }

        const latencyProxy = await PodkopShellMethods.getClashApiProxyLatency(
          section.code,
        );

        const success = latencyProxy.success && !latencyProxy.data.message;

        if (success) {
          return {
            success: true,
            latency: `${latencyProxy.data.delay} ms`,
          };
        }

        return {
          success: false,
          latency: _('Not responding'),
        };
      }

      const { latency, success } = await getLatency();

      return {
        state: success ? 'success' : 'error',
        key: section.displayName,
        value: latency,
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

  const atLeastOneGood = items.some((item) => item.state === 'success');

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
