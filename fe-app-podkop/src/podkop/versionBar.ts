import { PODKOP_LUCI_APP_VERSION } from '../constants';
import { compareVersions } from '../helpers/compareVersions';
import { luciText } from '../helpers/luciText';
import { PodkopShellMethods } from './methods';
import { logger } from './services';

// The version bar: a line under the apply bar, above the title and the tabs, so on every tab.
// It is there when the page and the backend are of different versions:
//   the page is older   after an update the browser may keep the page of the version before:
//                       it lacks what the new backend has and asks it for what it may no longer
//                       answer. Loaded past the cache, the page is the installed one;
//   the page is newer   the same after a downgrade; or podkop was not started again after an
//                       update: the backend that runs is asked, not the program that is
//                       installed. The page then offers what the backend does not know.
//
// The version of the page is the one its package wrote into the bundle (PODKOP_LUCI_APP_VERSION),
// the one of the backend its show_version, which every backend answers. They are ordered as
// Diagnostics orders the installed version and the latest release (compareVersions): a candidate
// is newer than the release it is named by, and what is not a version (the page of the sources,
// a backend built without one, no answer) has no order, so no bar.
//
// It is asked once, when the page loads, and nothing waits for it. Dismiss hides it in this tab
// until the browser closes it; another pair of versions is told anew.
//
// The bar reloads the page itself: Ctrl+F5 does not help in Chrome, which takes the files a page
// asks after its load event from the cache even then, and LuCI asks the files of a view after it
// (lab/runs/2026-11-24-0823-page).

const DISMISSED_KEY = 'podkop-version-dismissed';

// versionText is what the bar says of the two versions, '' for nothing: the same version, or
// either is not known.
export function versionText(page: string, backend: string): string {
  switch (compareVersions(page, backend)) {
    case -1:
      return _(
        'This page (version %s) is older than the backend (version %s): reload it without the cache',
      ).format(page, backend);
    case 1:
      return _(
        'This page (version %s) is newer than the backend (version %s): after an update restart podkop, after a downgrade reload this page without the cache',
      ).format(page, backend);
    default:
      return '';
  }
}

function readDismissed(): string | null {
  try {
    return sessionStorage.getItem(DISMISSED_KEY);
  } catch {
    return null;
  }
}

function writeDismissed(pair: string): void {
  try {
    sessionStorage.setItem(DISMISSED_KEY, pair);
  } catch {
    // no storage: hidden until the page is loaded again
  }
}

// reloadWithoutCache loads the page again with the files the router has now: each file of the
// view is asked past the cache, which then holds the new one, before an ordinary reload. The
// bodies are read to their end: a reload would cut them short, and the cache would not keep them.
export async function reloadWithoutCache(): Promise<void> {
  const files = performance
    .getEntriesByType('resource')
    .map((entry) => entry.name)
    .filter((name) => name.includes('/view/podkop/'));
  await Promise.all(
    files.map((file) =>
      fetch(file, { cache: 'reload' })
        .then((response) => response.arrayBuffer())
        .catch((err) => logger.warn('[VERSION]', file, err)),
    ),
  );
  location.reload();
}

// createVersionBar returns the element of the bar, hidden until the backend's version is known
// to be another than the page's.
export function createVersionBar(
  page: string = PODKOP_LUCI_APP_VERSION,
): HTMLElement {
  const bar = E('div', {
    id: 'podkop-version-bar',
    class: 'alert-message warning',
    role: 'status',
    'aria-live': 'polite',
    style: 'display: none',
  });
  PodkopShellMethods.showVersion()
    .then((backend) => {
      const text = versionText(page, backend);
      const pair = page + ' ' + backend;
      if (!text || readDismissed() === pair) return;
      const reload = E(
        'button',
        {
          class: 'btn cbi-button cbi-button-action important',
          type: 'button',
          click: () => {
            reload.disabled = true;
            reloadWithoutCache();
          },
        },
        [_('Reload without the cache')],
      );
      const dismiss = E(
        'button',
        {
          class: 'btn cbi-button cbi-button-neutral',
          type: 'button',
          click: () => {
            writeDismissed(pair);
            bar.style.display = 'none';
          },
        },
        [luciText('Dismiss')],
      );
      bar.appendChild(E('p', { class: 'podkop-apply-text' }, [text]));
      bar.appendChild(
        E('div', { class: 'podkop-apply-actions' }, [reload, dismiss]),
      );
      bar.style.display = '';
    })
    .catch((err) => logger.warn('[VERSION]', err));
  return bar;
}
