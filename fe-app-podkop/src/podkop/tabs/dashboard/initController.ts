import { onMount, preserveScrollForPage } from '../../../helpers';
import { prettyBytes } from '../../../helpers/prettyBytes';
import { CustomPodkopMethods, PodkopShellMethods } from '../../methods';
import { logger, store, StoreType } from '../../services';
import { renderSections, renderWidget } from './partials';
import { fetchServicesInfo } from '../../fetchers';
import { servicesStale, statsWidgets } from './helpers/statsWidgets';
import {
  canCheck,
  CHECK_QUEUE_LIMIT,
  detectIsBusy,
  isChecking,
  mayHang,
  oncePerControl,
  problemServers,
  problemTiles,
  widgetOfReport,
} from './helpers/detectWidget';
import { keepFocus } from './helpers/keepFocus';
import {
  checkedAgo,
  forceDetectProblem,
  stopsChecks,
  relayNotice,
  verdictLines,
} from './helpers/verdictText';
import { showToast } from '../../../helpers/showToast';
import type { Podkop } from '../../types';

// Fetchers

async function fetchDashboardSections() {
  const prev = store.get().sectionsWidget;

  store.set({
    sectionsWidget: {
      ...prev,
      failed: false,
    },
  });

  const { data, success } = await CustomPodkopMethods.getDashboardSections();

  if (!success) {
    logger.error('[DASHBOARD]', 'fetchDashboardSections: failed to fetch');
  }

  store.set({
    sectionsWidget: {
      latencyFetching: false,
      loading: false,
      failed: !success,
      data,
    },
  });
}

// The numbers of the dashboard come from the running backend: the method stats of its
// object on ubus, asked every 2 s while the tab is open and the page visible (the first two
// a second apart, for the first rates). The page used to read two websockets of the Clash
// API, one of which sent the whole list of the connections every second (141 KB/s at 300
// connections), and which a page of LuCI served over https cannot open.
const STATS_MS = 2000;
let statsTimers: ReturnType<typeof setTimeout>[] = [];
let lastStats: Podkop.Stats | undefined;
let servicesRead = 0;
let backendStats: (() => Promise<Podkop.Stats | number>) | undefined;

async function fetchStats() {
  if (document.hidden) {
    // the rates after a pause are of the next two answers
    lastStats = undefined;
    return;
  }
  backendStats ??= rpc.declare<Podkop.Stats | number>({
    object: 'podkop',
    method: 'stats',
    nobatch: true,
  });
  let current: Podkop.Stats | undefined;
  try {
    const reply = await backendStats();
    current = typeof reply === 'object' && reply !== null ? reply : undefined;
  } catch {
    // no object podkop: the backend does not run
  }
  if (!mounted) return;
  store.set(statsWidgets(current, lastStats));
  lastStats = current;
  if (
    servicesStale(
      current,
      store.get().servicesInfoWidget,
      servicesRead,
      Date.now(),
    )
  ) {
    // the backend came up or went away since the services were read: the grid with them
    servicesRead = Date.now();
    await Promise.all([fetchServicesInfo(), fetchDashboardSections()]);
  }
}

function startStats() {
  stopStats();
  fetchStats();
  statsTimers = [
    setTimeout(fetchStats, 1000),
    setInterval(fetchStats, STATS_MS),
  ];
}

function stopStats() {
  statsTimers.forEach((timer) => clearTimeout(timer));
  statsTimers = [];
  lastStats = undefined;
}

// The verdicts of the block detector come from the method detect of the backend, on a timer of
// their own and not with the sections: those ask the Clash API and the configuration, and a hiccup
// there fails the whole grid. A change of a verdict rebuilds the grid, so the age of a verdict,
// which changes with every answer, stays out of the store and is only read by its window.
const DETECT_IDLE_MS = 15000;
const DETECT_BUSY_MS = 2000;
let detectTimer: ReturnType<typeof setTimeout> | undefined;
let detectAsking = false;
let verdictAges: Record<string, { age: number; at: number }> = {};
// what a check still sends is left off when this changes: the queue was cancelled, the tab left
let checksRun = 0;

function scheduleDetect(wait: number) {
  clearTimeout(detectTimer);
  detectTimer = setTimeout(fetchDetect, wait);
}

function nextDetectWait() {
  return detectIsBusy(store.get().detectWidget)
    ? DETECT_BUSY_MS
    : DETECT_IDLE_MS;
}

async function fetchDetect() {
  // the answer on its way asks for the next one
  if (detectAsking) return;
  if (document.hidden) {
    scheduleDetect(nextDetectWait());
    return;
  }
  detectAsking = true;
  const run = checksRun;
  const report = await CustomPodkopMethods.getVerdicts();
  detectAsking = false;
  if (!mounted) return;
  // asked before a cancel, the answer still holds the old queue: the next one comes soon
  if (run !== checksRun) {
    scheduleDetect(DETECT_BUSY_MS);
    return;
  }
  if (report) {
    const now = Date.now();
    verdictAges = Object.fromEntries(
      Object.entries(report.verdicts).map(([tag, verdict]) => [
        tag,
        { age: verdict.age ?? 0, at: now },
      ]),
    );
    store.set({
      detectWidget: widgetOfReport(store.get().detectWidget, report, now),
    });
  }
  scheduleDetect(nextDetectWait());
}

function stopDetect() {
  clearTimeout(detectTimer);
  detectTimer = undefined;
  verdictAges = {};
  checksRun++;
}

function setDetect(change: Partial<StoreType['detectWidget']>) {
  store.set({ detectWidget: { ...store.get().detectWidget, ...change } });
}

// Handlers

// sendChecks asks the backend for the checks of servers, one call each: its queue keeps the order
// and runs them one at a time. The tiles show them as waiting from the first moment; one the
// backend does not take goes back at once.
async function sendChecks(tags: string[], section?: string, found?: number) {
  const run = checksRun;
  const requested = { ...store.get().detectWidget.requested };
  tags.forEach((tag) => (requested[tag] = Date.now()));
  setDetect(
    section ? { requested, batch: { section, tags, found } } : { requested },
  );
  scheduleDetect(DETECT_BUSY_MS);

  let skipped = 0;
  for (const tag of tags) {
    const reply = await CustomPodkopMethods.forceDetect(tag);
    if (run !== checksRun) return;

    const problem = forceDetectProblem(reply);
    if (!problem) continue;

    const { requested: current, batch } = store.get().detectWidget;
    const { [tag]: _sent, ...others } = current;
    const left = batch?.tags.filter((other) => other !== tag);
    setDetect({
      requested: others,
      batch: batch && left?.length ? { ...batch, tags: left } : null,
    });
    if (!section) {
      showToast(problem, 'error', 5000);
    } else if (stopsChecks(reply)) {
      showToast(problem, 'error', 5000);
      setDetect({ requested: {}, batch: null });
      return;
    } else {
      skipped++;
    }
  }
  if (skipped) {
    showToast(
      _(
        'Not queued: %d of %d. Their addresses were checked recently or are already in the queue, or they are gone.',
      ).format(skipped, tags.length),
      'error',
      5000,
    );
  }
  fetchDetect();
}

// askToCheck warns before a check of what the connections go through: its burst may freeze the
// destination for the real ones too.
function askToCheck(warning: string, check: () => void) {
  ui.showModal(_('Server check'), [
    E('p', {}, [warning]),
    E('p', {}, [relayNotice()]),
    E('div', { class: 'right' }, [
      E(
        'button',
        {
          class: 'cbi-button pdk-detect-modal__close',
          click: () => ui.hideModal(),
        },
        [_('Cancel')],
      ),
      ' ',
      E(
        'button',
        {
          class: 'cbi-button cbi-button-action pdk-detect-modal__confirm',
          click: () => {
            ui.hideModal();
            check();
          },
        },
        [_('Check server')],
      ),
    ]),
  ]);
}

const readForPress = oncePerControl();

// checkAfterRead reads what the connections go through at the press: a URL test may have switched
// since the grid was drawn. The check waits for that read, up to its bound; without an answer in
// time it goes by what the grid knows. A press of the same control meanwhile is ignored.
function checkAfterRead(
  control: string,
  servers: Podkop.Outbound[],
  warning: string,
  check: () => void,
) {
  return readForPress(
    control,
    () =>
      CustomPodkopMethods.getUsedTags(
        store.get().sectionsWidget.data.map(({ code }) => code),
      ),
    (used) => {
      if (!mounted) return;
      if (!servers.some((server) => mayHang(server, used))) return check();
      askToCheck(warning, check);
    },
  );
}

function handleCheckServer(outbound: Podkop.Outbound) {
  return checkAfterRead(
    `server:${outbound.code}`,
    [outbound],
    _(
      'New connections through this server may hang for a couple of minutes after the check starts.',
    ),
    () => sendChecks([outbound.code]),
  );
}

function handleCheckProblems(section: Podkop.OutboundGroup) {
  const detect = store.get().detectWidget;
  const servers = problemServers(section, detect);
  const found = problemTiles(section, detect).length;
  return checkAfterRead(
    `section:${section.code}`,
    servers,
    _(
      'One of these servers is in use. New connections through it may hang for a couple of minutes after its check starts.',
    ),
    () =>
      sendChecks(
        servers.map((server) => server.code),
        section.code,
        found > CHECK_QUEUE_LIMIT ? found : undefined,
      ),
  );
}

// the queue goes, the probe that runs goes on: its burst is out already
async function handleCancelChecks() {
  checksRun++;
  setDetect({ requested: {}, batch: null, queued: [] });
  const problem = forceDetectProblem(
    await CustomPodkopMethods.forceDetect('', true),
  );
  if (problem) showToast(problem, 'error');
  if (mounted) fetchDetect();
}

function handleShowVerdict(outbound: Podkop.Outbound) {
  const detect = store.get().detectWidget;
  const verdict = detect.verdicts[outbound.code];
  const known = verdictAges[outbound.code];
  const checking = isChecking(outbound.code, detect);
  const lines = [
    ...(detect.probing === outbound.code ? [_('Checking now…')] : []),
    ...(checking && detect.probing !== outbound.code
      ? [_('Waiting for its turn.')]
      : []),
    ...(verdict ? verdictLines(verdict) : []),
    ...(verdict?.source === 'active' && known
      ? [checkedAgo(known.age + (Date.now() - known.at) / 1000)]
      : []),
  ];
  // a title that is not in an array goes in as HTML, and the name may come from a subscription
  ui.showModal(
    [outbound.displayName],
    [
      ...lines.map((line) => E('p', {}, [line])),
      E('div', { class: 'right' }, [
        E(
          'button',
          {
            class: 'cbi-button pdk-detect-modal__close',
            click: () => ui.hideModal(),
          },
          [_('Close')],
        ),
        ...(!checking && canCheck(outbound, detect.noprobe)
          ? [
              ' ',
              E(
                'button',
                {
                  class: 'cbi-button cbi-button-action pdk-detect-modal__check',
                  click: () => {
                    ui.hideModal();
                    handleCheckServer(outbound);
                  },
                },
                [_('Check server')],
              ),
            ]
          : []),
      ]),
    ],
  );
}

async function handleChooseOutbound(selector: string, tag: string) {
  await PodkopShellMethods.setClashApiGroupProxy(selector, tag);
  await fetchDashboardSections();
}

async function handleTestGroupLatency(tag: string) {
  store.set({
    sectionsWidget: {
      ...store.get().sectionsWidget,
      latencyFetching: true,
    },
  });

  await PodkopShellMethods.getClashApiGroupLatency(tag);
  await fetchDashboardSections();

  store.set({
    sectionsWidget: {
      ...store.get().sectionsWidget,
      latencyFetching: false,
    },
  });
}

async function handleTestProxyLatency(tag: string) {
  store.set({
    sectionsWidget: {
      ...store.get().sectionsWidget,
      latencyFetching: true,
    },
  });

  await PodkopShellMethods.getClashApiProxyLatency(tag);
  await fetchDashboardSections();

  store.set({
    sectionsWidget: {
      ...store.get().sectionsWidget,
      latencyFetching: false,
    },
  });
}

// Renderer

async function renderSectionsWidget() {
  logger.debug('[DASHBOARD]', 'renderSectionsWidget');
  const sectionsWidget = store.get().sectionsWidget;
  const container = document.getElementById('dashboard-sections-grid');

  if (sectionsWidget.loading || sectionsWidget.failed) {
    const renderedWidget = renderSections({
      loading: sectionsWidget.loading,
      failed: sectionsWidget.failed,
      section: {
        code: '',
        displayName: '',
        outbounds: [],
        withTagSelect: false,
      },
      onTestLatency: () => {},
      onChooseOutbound: () => {},
      latencyFetching: sectionsWidget.latencyFetching,
    });

    return preserveScrollForPage(() => {
      container!.replaceChildren(renderedWidget);
    });
  }

  const renderedWidgets = sectionsWidget.data.map((section) =>
    renderSections({
      loading: sectionsWidget.loading,
      failed: sectionsWidget.failed,
      section,
      latencyFetching: sectionsWidget.latencyFetching,
      checks: {
        detect: store.get().detectWidget,
        onShowVerdict: handleShowVerdict,
        onCheckServer: handleCheckServer,
        onCheckProblems: handleCheckProblems,
        onCancelChecks: handleCancelChecks,
      },
      onTestLatency: (tag) => {
        if (section.withTagSelect) {
          return handleTestGroupLatency(tag);
        }

        return handleTestProxyLatency(tag);
      },
      onChooseOutbound: (selector, tag) => {
        handleChooseOutbound(selector, tag);
      },
    }),
  );

  return preserveScrollForPage(() => {
    keepFocus(container!, () => container!.replaceChildren(...renderedWidgets));
  });
}

async function renderBandwidthWidget() {
  logger.debug('[DASHBOARD]', 'renderBandwidthWidget');
  const traffic = store.get().bandwidthWidget;

  const container = document.getElementById('dashboard-widget-traffic');

  if (traffic.loading || traffic.failed) {
    const renderedWidget = renderWidget({
      loading: traffic.loading,
      failed: traffic.failed,
      title: '',
      items: [],
    });

    return container!.replaceChildren(renderedWidget);
  }

  const renderedWidget = renderWidget({
    loading: traffic.loading,
    failed: traffic.failed,
    title: _('Traffic'),
    items: [
      { key: _('Uplink'), value: `${prettyBytes(traffic.data.up)}/s` },
      { key: _('Downlink'), value: `${prettyBytes(traffic.data.down)}/s` },
    ],
  });

  container!.replaceChildren(renderedWidget);
}

async function renderTrafficTotalWidget() {
  logger.debug('[DASHBOARD]', 'renderTrafficTotalWidget');
  const trafficTotalWidget = store.get().trafficTotalWidget;

  const container = document.getElementById('dashboard-widget-traffic-total');

  if (trafficTotalWidget.loading || trafficTotalWidget.failed) {
    const renderedWidget = renderWidget({
      loading: trafficTotalWidget.loading,
      failed: trafficTotalWidget.failed,
      title: '',
      items: [],
    });

    return container!.replaceChildren(renderedWidget);
  }

  const renderedWidget = renderWidget({
    loading: trafficTotalWidget.loading,
    failed: trafficTotalWidget.failed,
    title: _('Traffic Total'),
    items: [
      {
        key: _('Uplink'),
        value: String(prettyBytes(trafficTotalWidget.data.uploadTotal)),
      },
      {
        key: _('Downlink'),
        value: String(prettyBytes(trafficTotalWidget.data.downloadTotal)),
      },
    ],
  });

  container!.replaceChildren(renderedWidget);
}

async function renderSystemInfoWidget() {
  logger.debug('[DASHBOARD]', 'renderSystemInfoWidget');
  const systemInfoWidget = store.get().systemInfoWidget;

  const container = document.getElementById('dashboard-widget-system-info');

  if (systemInfoWidget.loading || systemInfoWidget.failed) {
    const renderedWidget = renderWidget({
      loading: systemInfoWidget.loading,
      failed: systemInfoWidget.failed,
      title: '',
      items: [],
    });

    return container!.replaceChildren(renderedWidget);
  }

  const renderedWidget = renderWidget({
    loading: systemInfoWidget.loading,
    failed: systemInfoWidget.failed,
    title: _('System info'),
    items: [
      {
        key: _('Active Connections'),
        value: String(systemInfoWidget.data.connections),
      },
      {
        key: _('Memory Usage'),
        value: String(prettyBytes(systemInfoWidget.data.memory)),
      },
    ],
  });

  container!.replaceChildren(renderedWidget);
}

async function renderServicesInfoWidget() {
  logger.debug('[DASHBOARD]', 'renderServicesInfoWidget');
  const servicesInfoWidget = store.get().servicesInfoWidget;

  const container = document.getElementById('dashboard-widget-service-info');

  if (servicesInfoWidget.loading || servicesInfoWidget.failed) {
    const renderedWidget = renderWidget({
      loading: servicesInfoWidget.loading,
      failed: servicesInfoWidget.failed,
      title: '',
      items: [],
    });

    return container!.replaceChildren(renderedWidget);
  }

  const renderedWidget = renderWidget({
    loading: servicesInfoWidget.loading,
    failed: servicesInfoWidget.failed,
    title: _('Services info'),
    items: [
      // the process of podkop, sing-box inside it, and whether the router starts it
      {
        key: _('Podkop'),
        value: servicesInfoWidget.data.singbox
          ? _('✔ Running')
          : _('✘ Stopped'),
        attributes: {
          class: servicesInfoWidget.data.singbox
            ? 'pdk_dashboard-page__widgets-section__item__row--success'
            : 'pdk_dashboard-page__widgets-section__item__row--error',
        },
      },
      {
        key: _('Autostart'),
        value: servicesInfoWidget.data.podkop
          ? _('✔ Enabled')
          : _('✘ Disabled'),
        attributes: {
          class: servicesInfoWidget.data.podkop
            ? 'pdk_dashboard-page__widgets-section__item__row--success'
            : 'pdk_dashboard-page__widgets-section__item__row--error',
        },
      },
    ],
  });

  container!.replaceChildren(renderedWidget);
}

async function onStoreUpdate(
  next: StoreType,
  prev: StoreType,
  diff: Partial<StoreType>,
) {
  // the skeleton of the grid has nothing of the detector to show
  if (
    diff.sectionsWidget ||
    (diff.detectWidget &&
      !next.sectionsWidget.loading &&
      !next.sectionsWidget.failed)
  ) {
    renderSectionsWidget();
  }

  if (diff.bandwidthWidget) {
    renderBandwidthWidget();
  }

  if (diff.trafficTotalWidget) {
    renderTrafficTotalWidget();
  }

  if (diff.systemInfoWidget) {
    renderSystemInfoWidget();
  }

  if (diff.servicesInfoWidget) {
    renderServicesInfoWidget();
  }
}

// The controller starts once a page: LuCI asks the value of the dummy field that starts it
// at every render and after every save, and each start used to add a listener of the tabs that
// was never taken away (each opening of the tab did its work as many times). It mounts at
// every opening of the tab and unmounts when another tab opens; a render of LuCI while the tab
// is open (after a save) mounts it again once, on the new elements.
let started = false;
let mounted = false;
let remounting = false;

async function onPageMount() {
  // Cleanup before mount
  onPageUnmount();
  mounted = true;

  // Add new listener
  store.subscribe(onStoreUpdate);

  // The chips may come before the grid, the grid then draws them
  fetchDetect();

  // Initial sections fetch
  await fetchDashboardSections();
  await fetchServicesInfo();
  servicesRead = Date.now();
  // the tab may have been left while the answers came
  if (!mounted) return;
  startStats();
}

function onPageUnmount() {
  mounted = false;
  // Remove old listener
  store.unsubscribe(onStoreUpdate);
  // Clear store
  store.reset([
    'bandwidthWidget',
    'trafficTotalWidget',
    'systemInfoWidget',
    'servicesInfoWidget',
    'sectionsWidget',
    'detectWidget',
  ]);
  stopStats();
  stopDetect();
}

function isCurrent() {
  return store.get().tabService.current === 'dashboard';
}

export async function initController(): Promise<void> {
  if (started) {
    if (mounted && !remounting) {
      remounting = true;
      onMount(
        'dashboard-status',
        document.getElementById('dashboard-status'),
      ).then(() => {
        remounting = false;
        if (mounted) onPageMount();
      });
    }
    return;
  }
  started = true;

  store.subscribe((next, prev, diff) => {
    if (
      !diff.tabService ||
      next.tabService.current === prev.tabService.current
    ) {
      return;
    }
    logger.debug('[DASHBOARD]', 'active tab:', next.tabService.current);
    if (isCurrent()) {
      onMount('dashboard-status').then(() => {
        if (isCurrent() && !mounted) onPageMount();
      });
    } else if (mounted) {
      onPageUnmount();
    }
  });

  onMount('dashboard-status').then(() => {
    if (isCurrent() && !mounted) onPageMount();
  });
}
