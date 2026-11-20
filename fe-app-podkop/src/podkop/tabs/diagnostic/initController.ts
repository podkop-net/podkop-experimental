import { onMount, preserveScrollForPage } from '../../../helpers';
import { runDnsCheck } from './checks/runDnsCheck';
import { runSingBoxCheck } from './checks/runSingBoxCheck';
import { runNftCheck } from './checks/runNftCheck';
import { runFakeIPCheck } from './checks/runFakeIPCheck';
import { loadingDiagnosticsChecksStore } from './diagnostic.store';
import { logger, store, StoreType } from '../../services';
import {
  renderAvailableActions,
  renderCheckSection,
  renderRunAction,
  renderSystemInfo,
} from './partials';
import { PodkopShellMethods, RemoteFakeIPMethods } from '../../methods';
import { fetchServicesInfo } from '../../fetchers';
import { normalizeCompiledVersion } from '../../../helpers/normalizeCompiledVersion';
import { renderModal } from '../../../partials';
import { PODKOP_LUCI_APP_VERSION } from '../../../constants';
import { showToast } from '../../../helpers/showToast';
import { renderWikiDisclaimer } from './partials/renderWikiDisclaimer';
import { runSectionsCheck } from './checks/runSectionsCheck';
import { getPodkopVersionRow } from './helpers/getPodkopVersionRow';
import { getLatestRelease } from '../../../helpers/getLatestRelease';

async function fetchSystemInfo() {
  // the latest release is asked of GitHub by the browser, not by the router, and kept for the
  // version of this page (install.sh upgrades the page and the backend together); the page's
  // version is known at once, so the two are asked at the same time
  const [systemInfo, latest] = await Promise.all([
    PodkopShellMethods.getSystemInfo(),
    getLatestRelease(PODKOP_LUCI_APP_VERSION),
  ]);

  if (systemInfo.success) {
    store.set({
      diagnosticsSystemInfo: {
        loading: false,
        ...systemInfo.data,
        podkop_latest_version: latest || _('unknown'),
      },
    });
  } else {
    store.set({
      diagnosticsSystemInfo: {
        loading: false,
        podkop_version: _('unknown'),
        podkop_latest_version: _('unknown'),
        luci_app_version: _('unknown'),
        sing_box_version: _('unknown'),
        openwrt_version: _('unknown'),
        device_model: _('unknown'),
      },
    });
  }
}

function renderDiagnosticsChecks() {
  logger.debug('[DIAGNOSTIC]', 'renderDiagnosticsChecks');
  const diagnosticsChecks = store
    .get()
    .diagnosticsChecks.sort((a, b) => a.order - b.order);
  const container = document.getElementById('pdk_diagnostic-page-checks');

  const renderedDiagnosticsChecks = diagnosticsChecks.map((check) =>
    renderCheckSection(check),
  );

  return preserveScrollForPage(() => {
    container!.replaceChildren(...renderedDiagnosticsChecks);
  });
}

function renderDiagnosticRunActionWidget() {
  logger.debug('[DIAGNOSTIC]', 'renderDiagnosticRunActionWidget');

  const { loading } = store.get().diagnosticsRunAction;
  const container = document.getElementById('pdk_diagnostic-page-run-check');

  const renderedAction = renderRunAction({
    loading,
    click: () => runChecks(),
  });

  return preserveScrollForPage(() => {
    container!.replaceChildren(renderedAction);
  });
}

async function handleRestart() {
  const diagnosticsActions = store.get().diagnosticsActions;
  store.set({
    diagnosticsActions: {
      ...diagnosticsActions,
      restart: { loading: true },
    },
  });

  try {
    await PodkopShellMethods.restart();
  } catch (e) {
    logger.error('[DIAGNOSTIC]', 'handleRestart - e', e);
  } finally {
    setTimeout(async () => {
      await fetchServicesInfo();
      store.set({
        diagnosticsActions: {
          ...diagnosticsActions,
          restart: { loading: false },
        },
      });
      store.reset(['diagnosticsChecks']);
    }, 5000);
  }
}

async function handleStop() {
  const diagnosticsActions = store.get().diagnosticsActions;
  store.set({
    diagnosticsActions: {
      ...diagnosticsActions,
      stop: { loading: true },
    },
  });

  try {
    await PodkopShellMethods.stop();
  } catch (e) {
    logger.error('[DIAGNOSTIC]', 'handleStop - e', e);
  } finally {
    await fetchServicesInfo();
    store.set({
      diagnosticsActions: {
        ...diagnosticsActions,
        stop: { loading: false },
      },
    });
    store.reset(['diagnosticsChecks']);
  }
}

async function handleStart() {
  const diagnosticsActions = store.get().diagnosticsActions;
  store.set({
    diagnosticsActions: {
      ...diagnosticsActions,
      start: { loading: true },
    },
  });

  try {
    await PodkopShellMethods.start();
  } catch (e) {
    logger.error('[DIAGNOSTIC]', 'handleStart - e', e);
  } finally {
    setTimeout(async () => {
      await fetchServicesInfo();
      store.set({
        diagnosticsActions: {
          ...diagnosticsActions,
          start: { loading: false },
        },
      });
      store.reset(['diagnosticsChecks']);
    }, 5000);
  }
}

async function handleEnable() {
  const diagnosticsActions = store.get().diagnosticsActions;
  store.set({
    diagnosticsActions: {
      ...diagnosticsActions,
      enable: { loading: true },
    },
  });

  try {
    await PodkopShellMethods.enable();
  } catch (e) {
    logger.error('[DIAGNOSTIC]', 'handleEnable - e', e);
  } finally {
    await fetchServicesInfo();
    store.set({
      diagnosticsActions: {
        ...diagnosticsActions,
        enable: { loading: false },
      },
    });
  }
}

async function handleDisable() {
  const diagnosticsActions = store.get().diagnosticsActions;
  store.set({
    diagnosticsActions: {
      ...diagnosticsActions,
      disable: { loading: true },
    },
  });

  try {
    await PodkopShellMethods.disable();
  } catch (e) {
    logger.error('[DIAGNOSTIC]', 'handleDisable - e', e);
  } finally {
    await fetchServicesInfo();
    store.set({
      diagnosticsActions: {
        ...diagnosticsActions,
        disable: { loading: false },
      },
    });
  }
}

async function handleShowGlobalCheck() {
  const diagnosticsActions = store.get().diagnosticsActions;
  store.set({
    diagnosticsActions: {
      ...diagnosticsActions,
      globalCheck: { loading: true },
    },
  });

  // this browser knocks on a check name meanwhile: the report tells whether its DNS
  // question and its connections came to sing-box, and where they were lost
  const knock = RemoteFakeIPMethods.knockFakeIpRepeatedly();
  try {
    const globalCheck = await PodkopShellMethods.globalCheck(
      knock.label,
      knock.port,
    );

    if (globalCheck.success) {
      ui.showModal(
        _('Global check'),
        renderModal(globalCheck.data as string, 'global_check'),
      );
    } else {
      logger.error('[DIAGNOSTIC]', 'handleShowGlobalCheck - e', globalCheck);
      showToast(_('Failed to execute!'), 'error');
    }
  } catch (e) {
    logger.error('[DIAGNOSTIC]', 'handleShowGlobalCheck - e', e);
    showToast(_('Failed to execute!'), 'error');
  } finally {
    knock.stop();
    store.set({
      diagnosticsActions: {
        ...diagnosticsActions,
        globalCheck: { loading: false },
      },
    });
  }
}

async function handleViewLogs() {
  const diagnosticsActions = store.get().diagnosticsActions;
  store.set({
    diagnosticsActions: {
      ...diagnosticsActions,
      viewLogs: { loading: true },
    },
  });

  try {
    const viewLogs = await PodkopShellMethods.checkLogs();

    if (viewLogs.success) {
      ui.showModal(
        _('View logs'),
        renderModal(viewLogs.data as string, 'view_logs'),
      );
    } else {
      logger.error('[DIAGNOSTIC]', 'handleViewLogs - e', viewLogs);
      showToast(_('Failed to execute!'), 'error');
    }
  } catch (e) {
    logger.error('[DIAGNOSTIC]', 'handleViewLogs - e', e);
    showToast(_('Failed to execute!'), 'error');
  } finally {
    store.set({
      diagnosticsActions: {
        ...diagnosticsActions,
        viewLogs: { loading: false },
      },
    });
  }
}

async function handleShowSingBoxConfig() {
  const diagnosticsActions = store.get().diagnosticsActions;
  store.set({
    diagnosticsActions: {
      ...diagnosticsActions,
      showSingBoxConfig: { loading: true },
    },
  });

  try {
    const showSingBoxConfig = await PodkopShellMethods.showSingBoxConfig();

    if (showSingBoxConfig.success) {
      ui.showModal(
        _('Show sing-box config'),
        renderModal(
          JSON.stringify(showSingBoxConfig.data, null, 2),
          'show_sing_box_config',
        ),
      );
    } else {
      logger.error(
        '[DIAGNOSTIC]',
        'handleShowSingBoxConfig - e',
        showSingBoxConfig,
      );
      showToast(_('Failed to execute!'), 'error');
    }
  } catch (e) {
    logger.error('[DIAGNOSTIC]', 'handleShowSingBoxConfig - e', e);
    showToast(_('Failed to execute!'), 'error');
  } finally {
    store.set({
      diagnosticsActions: {
        ...diagnosticsActions,
        showSingBoxConfig: { loading: false },
      },
    });
  }
}

function renderWikiDisclaimerWidget() {
  const diagnosticsChecks = store.get().diagnosticsChecks;

  function getWikiKind() {
    const allResults = diagnosticsChecks.map((check) => check.state);

    if (allResults.includes('error')) {
      return 'error';
    }

    if (allResults.includes('warning')) {
      return 'warning';
    }

    return 'default';
  }

  const container = document.getElementById('pdk_diagnostic-page-wiki');

  return preserveScrollForPage(() => {
    container!.replaceChildren(renderWikiDisclaimer(getWikiKind()));
  });
}

function renderDiagnosticAvailableActionsWidget() {
  const diagnosticsActions = store.get().diagnosticsActions;
  const servicesInfoWidget = store.get().servicesInfoWidget;
  logger.debug('[DIAGNOSTIC]', 'renderDiagnosticAvailableActionsWidget');

  const podkopEnabled = Boolean(servicesInfoWidget.data.podkop);
  const singBoxRunning = Boolean(servicesInfoWidget.data.singbox);
  const atLeastOneServiceCommandLoading =
    servicesInfoWidget.loading ||
    diagnosticsActions.restart.loading ||
    diagnosticsActions.start.loading ||
    diagnosticsActions.stop.loading;

  const container = document.getElementById('pdk_diagnostic-page-actions');

  const renderedActions = renderAvailableActions({
    restart: {
      loading: diagnosticsActions.restart.loading,
      visible: true,
      onClick: handleRestart,
      disabled: atLeastOneServiceCommandLoading,
    },
    start: {
      loading: diagnosticsActions.start.loading,
      visible: !singBoxRunning,
      onClick: handleStart,
      disabled: atLeastOneServiceCommandLoading,
    },
    stop: {
      loading: diagnosticsActions.stop.loading,
      visible: singBoxRunning,
      onClick: handleStop,
      disabled: atLeastOneServiceCommandLoading,
    },
    enable: {
      loading: diagnosticsActions.enable.loading,
      visible: !podkopEnabled,
      onClick: handleEnable,
      disabled: atLeastOneServiceCommandLoading,
    },
    disable: {
      loading: diagnosticsActions.disable.loading,
      visible: podkopEnabled,
      onClick: handleDisable,
      disabled: atLeastOneServiceCommandLoading,
    },
    globalCheck: {
      loading: diagnosticsActions.globalCheck.loading,
      visible: true,
      onClick: handleShowGlobalCheck,
      disabled: atLeastOneServiceCommandLoading,
    },
    viewLogs: {
      loading: diagnosticsActions.viewLogs.loading,
      visible: true,
      onClick: handleViewLogs,
      disabled: atLeastOneServiceCommandLoading,
    },
    showSingBoxConfig: {
      loading: diagnosticsActions.showSingBoxConfig.loading,
      visible: true,
      onClick: handleShowSingBoxConfig,
      disabled: atLeastOneServiceCommandLoading,
    },
  });

  return preserveScrollForPage(() => {
    container!.replaceChildren(renderedActions);
  });
}

function renderDiagnosticSystemInfoWidget() {
  logger.debug('[DIAGNOSTIC]', 'renderDiagnosticSystemInfoWidget');
  const diagnosticsSystemInfo = store.get().diagnosticsSystemInfo;

  const container = document.getElementById('pdk_diagnostic-page-system-info');

  const renderedSystemInfo = renderSystemInfo({
    items: [
      getPodkopVersionRow(diagnosticsSystemInfo),
      {
        key: 'Luci App',
        value: normalizeCompiledVersion(PODKOP_LUCI_APP_VERSION),
      },
      {
        key: 'Engine',
        value:
          diagnosticsSystemInfo.engine ||
          diagnosticsSystemInfo.sing_box_version,
      },
      {
        key: 'OS',
        value: diagnosticsSystemInfo.openwrt_version,
      },
      {
        key: 'Device',
        value: diagnosticsSystemInfo.device_model,
      },
    ],
  });

  return preserveScrollForPage(() => {
    container!.replaceChildren(renderedSystemInfo);
  });
}

async function onStoreUpdate(
  next: StoreType,
  prev: StoreType,
  diff: Partial<StoreType>,
) {
  if (diff.diagnosticsChecks) {
    renderDiagnosticsChecks();
    renderWikiDisclaimerWidget();
  }

  if (diff.diagnosticsRunAction) {
    renderDiagnosticRunActionWidget();
  }

  if (diff.diagnosticsActions || diff.servicesInfoWidget) {
    renderDiagnosticAvailableActionsWidget();
  }

  if (diff.diagnosticsSystemInfo) {
    renderDiagnosticSystemInfoWidget();
  }
}

async function runChecks() {
  try {
    store.set({
      diagnosticsRunAction: { loading: true },
      diagnosticsChecks: loadingDiagnosticsChecksStore.diagnosticsChecks,
    });

    // one connection to a check name serves the nftables and the FakeIP check
    const label = RemoteFakeIPMethods.knockFakeIp();

    // no check needs the result of another: they run at once, each shows its own
    const results = await Promise.allSettled([
      runDnsCheck(),
      runSingBoxCheck(),
      runNftCheck(label),
      runSectionsCheck(),
      runFakeIPCheck(label),
    ]);

    results.forEach((result) => {
      if (result.status === 'rejected') {
        logger.error('[DIAGNOSTIC]', 'runChecks - e', result.reason);
      }
    });
  } catch (e) {
    logger.error('[DIAGNOSTIC]', 'runChecks - e', e);
  } finally {
    store.set({ diagnosticsRunAction: { loading: false } });
  }
}

// The controller starts once a page and mounts at every opening of the tab (see the same
// in the dashboard: LuCI starts it at every render and after every save).
let started = false;
let mounted = false;
let remounting = false;

function onPageMount() {
  // Cleanup before mount
  onPageUnmount();
  mounted = true;

  // Add new listener
  store.subscribe(onStoreUpdate);

  // Initial checks render
  renderDiagnosticsChecks();

  // Initial run checks action render
  renderDiagnosticRunActionWidget();

  // Initial available actions render
  renderDiagnosticAvailableActionsWidget();

  // Initial system info render
  renderDiagnosticSystemInfoWidget();

  // Initial Wiki disclaimer render
  renderWikiDisclaimerWidget();

  // Initial services info fetch
  fetchServicesInfo();

  // Initial system info fetch
  fetchSystemInfo();
}

function onPageUnmount() {
  mounted = false;
  // Remove old listener
  store.unsubscribe(onStoreUpdate);

  // Clear store
  store.reset([
    'diagnosticsActions',
    'diagnosticsSystemInfo',
    'diagnosticsChecks',
    'diagnosticsRunAction',
  ]);
}

function isCurrent() {
  return store.get().tabService.current === 'diagnostic';
}

export async function initController(): Promise<void> {
  if (started) {
    if (mounted && !remounting) {
      remounting = true;
      onMount(
        'diagnostic-status',
        document.getElementById('diagnostic-status'),
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
    logger.debug('[DIAGNOSTIC]', 'active tab:', next.tabService.current);
    if (isCurrent()) {
      onMount('diagnostic-status').then(() => {
        if (isCurrent() && !mounted) onPageMount();
      });
    } else if (mounted) {
      onPageUnmount();
    }
  });

  onMount('diagnostic-status').then(() => {
    if (isCurrent() && !mounted) onPageMount();
  });
}
