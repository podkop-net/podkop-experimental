import { PodkopShellMethods } from './methods';
import { logger } from './services';
import { Podkop } from './types';
import { withTimeout } from '../helpers';

// The apply bar: a line above the title and the tabs of the page, so on every tab. The page
// saves in three ways (the Save of a window, the Save of the footer, Save & Apply) and stages
// changes when a window opens; only an apply changes what the router does. The bar tells:
//   pending  the changes of podkop's settings saved in this login and not applied, with
//            Save & Apply, Show (LuCI's list of the changes) and Revert;
//   waiting  an apply was asked: the page waits for the backend's result;
//   applied  "Applied HH:MM: <the message of the backend>";
//   refused  the backend did not take the settings, its reason;
//   unknown  no result came in time; stopped: podkop does not run, nothing applies them.
//
// Only podkop's changes are counted: the page writes no other configuration (its ACL), and
// the backend's result is of podkop's settings only; LuCI's own indicator counts all of them.
// LuCI applies and reverts every change of the login at once, so the bar says how many other
// pages have, when there are some: its buttons take them too.
//
// An apply is seen where LuCI starts it: ui.changes.apply, which the Save & Apply of the
// footer, of LuCI's list of changes and of this bar all call. Before it goes on, the page reads
// the changes and the backend's status: an apply without a change of podkop does not reach
// the backend (procd's reload trigger is of podkop's configuration), and the last result's
// time before it ("base") is what a new result is told from — the router's clock compared
// with itself, whatever the clock of the browser says. LuCI reloads the page once the apply
// is confirmed, so what the page waits for is kept in sessionStorage, and the page that loads
// asks get_status until last_at is another than the base.

// The times, measured on the pk8 stand (OpenWrt 24.10.8 in a container, LuCI's defaults: holdoff
// 4 s, display 1.5 s; 7 applies, lab/runs/2026-11-23-applybar/RESULTS.md), from LuCI's apply
// request: the backend's new last_at after 1052-1102 ms (procd's reload trigger waits 1 s, the
// apply itself took 9-53 ms), uci-applied after 4087-4108 ms, LuCI's reload after 5615-5664 ms;
// the first get_status of the page LuCI loaded had the result every time, the bar showed it after
// 5896-6085 ms. A get_status of the page took 47-56 ms (in the backend, ubus podkop.run).
// A router waits longer only for its own apply: 4.4 s for a configuration kept running with
// 100 000 subnets (arm64 in qemu), 7.6 s for a start of the owner's router at boot, 23 s for a
// start in a VM (notes/handoff/research_notes: podkop08/results/measure, dns-after-reboot,
// podkop-exp/diag). So: a get_status a second while it waits (the result shown at most a second
// after it is there, for a call of some 50 ms a second) and 60 s from the apply in all (more
// than twice the slowest start known, 23 s, with LuCI's 6 s before the reload).
export const APPLY_POLL_MS = 1000;
export const APPLY_DEADLINE_MS = 60000;
// a record older than this when a page loads is of another visit: dropped unseen
const STALE_MS = 2 * APPLY_DEADLINE_MS;
// how long an apply waits for the reads before it (an answer of the running backend takes
// milliseconds; a backend that does not run is asked through a start of the program)
const BEFORE_MS = 3000;

const RECORD_KEY = 'podkop-apply';

export type ResultKind = 'applied' | 'refused' | 'unknown' | 'stopped';

export interface ApplyResult {
  kind: ResultKind;
  // the backend's time of the result (RFC 3339) and its message
  at?: string;
  message?: string;
}

export interface ApplyRecord {
  // when the apply was asked, by the clock of the browser: the deadline counts from it
  started: number;
  // last_at of the backend before the apply, null when it had no result yet
  base: string | null;
  // whether a backend ran before the apply
  backend: boolean;
  result?: ApplyResult;
}

export interface ChangeCount {
  podkop: number;
  other: number;
}

// countChanges counts the change records of uci.changes() (LuCI's indicator counts the same):
// those of podkop, and those of other configurations.
export function countChanges(changes: unknown): ChangeCount {
  const count = { podkop: 0, other: 0 };
  if (!changes || typeof changes !== 'object') return count;
  for (const [config, list] of Object.entries(changes)) {
    const n = Array.isArray(list) ? list.length : 0;
    if (config === 'podkop') count.podkop += n;
    else count.other += n;
  }
  return count;
}

// tellsResult: a status of a backend that tells its result (0.8.22 on: "backend" is always
// there); the backend of 0.8.21 answers "enabled" and "status" only.
export function tellsResult(status: unknown): status is Podkop.GetStatus {
  return (
    !!status &&
    typeof status === 'object' &&
    typeof (status as Podkop.GetStatus).backend === 'boolean'
  );
}

// newRecord is what an apply asked at now waits for: a result after the one the backend had
// (fresh: read just before the apply; known: read when the page loaded, when the fresh read
// failed). None when no read tells a result: a backend of 0.8.21, or nothing answered.
export function newRecord(
  fresh: unknown,
  known: unknown,
  now: number,
): ApplyRecord | null {
  const status = tellsResult(fresh) ? fresh : tellsResult(known) ? known : null;
  if (!status) return null;
  return {
    started: now,
    base: status.last_at || null,
    backend: !!status.backend,
  };
}

// judge tells what an apply came to from a status of the backend (null: none was read), or
// undefined while it is still to come.
export function judge(
  record: ApplyRecord,
  status: Podkop.GetStatus | null,
  now: number,
): ApplyResult | undefined {
  if (
    status?.backend &&
    status.last &&
    status.last_at &&
    status.last_at !== record.base
  ) {
    return {
      kind: status.last.ok ? 'applied' : 'refused',
      at: status.last_at,
      message: status.last.message,
    };
  }
  // no backend before the apply nor now: the settings are taken when podkop starts
  if (status?.backend === false && !record.backend) return { kind: 'stopped' };
  if (now - record.started >= APPLY_DEADLINE_MS) {
    return { kind: status?.backend === false ? 'stopped' : 'unknown' };
  }
  return undefined;
}

// parseRecord reads a record kept by an earlier page of this tab; null when there is none,
// it is not one, or it is of another visit.
export function parseRecord(
  text: string | null,
  now: number,
): ApplyRecord | null {
  if (!text) return null;
  try {
    const value = JSON.parse(text) as ApplyRecord;
    if (
      !value ||
      typeof value.started !== 'number' ||
      (value.base !== null && typeof value.base !== 'string') ||
      typeof value.backend !== 'boolean' ||
      Math.abs(now - value.started) > STALE_MS
    ) {
      return null;
    }
    return value;
  } catch {
    return null;
  }
}

// clockOf is the time of a result for a person: HH:MM of the browser's zone.
export function clockOf(at: string | undefined): string {
  const time = Date.parse(at ?? '');
  if (isNaN(time)) return at ?? '';
  const date = new Date(time);
  const two = (n: number) => String(n).padStart(2, '0');
  return two(date.getHours()) + ':' + two(date.getMinutes());
}

export type BarKind = 'none' | 'pending' | 'waiting' | ResultKind;
export type BarButton = 'apply' | 'show' | 'revert' | 'dismiss';

export interface BarState {
  changes: ChangeCount;
  waiting: boolean;
  result?: ApplyResult;
}

export interface BarView {
  kind: BarKind;
  text: string;
  buttons: BarButton[];
}

// barView is what the bar shows: an apply waited for, else changes not applied, else the
// result of the last apply.
export function barView(state: BarState): BarView {
  if (state.waiting) {
    return { kind: 'waiting', text: _('Applying the settings…'), buttons: [] };
  }
  if (state.changes.podkop > 0) {
    let text = _('Changes saved but not applied: %d').format(
      state.changes.podkop,
    );
    if (state.changes.other > 0) {
      text +=
        ' ' +
        _('(and %d on other pages: the buttons take them too)').format(
          state.changes.other,
        );
    }
    return { kind: 'pending', text, buttons: ['apply', 'show', 'revert'] };
  }
  const result = state.result;
  if (!result) return { kind: 'none', text: '', buttons: [] };
  switch (result.kind) {
    case 'applied':
      return {
        kind: 'applied',
        text: _('Applied %s: %s').format(clockOf(result.at), result.message),
        buttons: ['dismiss'],
      };
    case 'refused':
      return {
        kind: 'refused',
        text: _('Not applied %s: %s').format(
          clockOf(result.at),
          result.message,
        ),
        buttons: ['dismiss'],
      };
    case 'stopped':
      return {
        kind: 'stopped',
        text: _(
          'Saved. podkop does not run: the settings take effect when it starts',
        ),
        buttons: ['dismiss'],
      };
    default:
      return {
        kind: 'unknown',
        text: _(
          'podkop did not tell within %d s whether it applied the settings: see Diagnostics → View logs',
        ).format(APPLY_DEADLINE_MS / 1000),
        buttons: ['dismiss'],
      };
  }
}

// the classes of LuCI's alert-message each kind takes, in the five themes the page is tried
// in: danger and error both (openwrt2020 colours danger only, argon error only)
const BAR_CLASSES: Record<BarKind, string> = {
  none: '',
  pending: 'warning',
  waiting: 'notice spinning',
  applied: 'success',
  refused: 'danger error',
  unknown: 'warning',
  stopped: 'warning',
};

export interface LuciChanges {
  apply(checked?: boolean): unknown;
  revert(): unknown;
  displayChanges(): unknown;
  renderChangeIndicator(changes: unknown): unknown;
  displayStatus?(type: string | false, content?: unknown): unknown;
  podkopWrapped?: boolean;
}

// wrapApply makes target.apply run before() first, at most one at a time, and LuCI's apply
// after it whatever before() came to.
export function wrapApply(
  target: LuciChanges,
  before: () => Promise<unknown>,
): void {
  if (target.podkopWrapped || typeof target.apply !== 'function') return;
  const original = target.apply;
  let starting = false;
  target.apply = function (this: LuciChanges | undefined, checked?: boolean) {
    if (starting) return;
    starting = true;
    const self = this || target;
    const go = () => {
      starting = false;
      return original.call(self, checked);
    };
    let first: Promise<unknown>;
    try {
      first = Promise.resolve(before());
    } catch (err) {
      first = Promise.reject(err);
    }
    first.then(go, go);
  };
  target.podkopWrapped = true;
}

function readRecord(): ApplyRecord | null {
  try {
    return parseRecord(sessionStorage.getItem(RECORD_KEY), Date.now());
  } catch {
    return null;
  }
}

function writeRecord(record: ApplyRecord | null): void {
  try {
    if (record) sessionStorage.setItem(RECORD_KEY, JSON.stringify(record));
    else sessionStorage.removeItem(RECORD_KEY);
  } catch {
    // no storage: the page that applies still shows what it learns
  }
}

async function readStatus(): Promise<Podkop.GetStatus | null> {
  const reply = await PodkopShellMethods.getStatus();
  return reply.success && reply.data && typeof reply.data === 'object'
    ? reply.data
    : null;
}

function luciChanges(): LuciChanges | undefined {
  return (ui as unknown as { changes?: LuciChanges }).changes;
}

// LuCI's own words for its buttons: the bar's buttons are named as those of the footer and of
// LuCI's list of changes, in LuCI's translation (an alias of _ the extraction of podkop's
// catalogue does not take)
const luciText: (key: string) => string = (key) => _(key);

export interface ApplyBarOptions {
  // the Save & Apply of the page's footer (view.handleSaveApply): the form saved, with the
  // page's checks, then applied
  saveApply: (event: Event) => unknown;
}

// createApplyBar makes the bar, starts what keeps it up to date, and returns its element.
export function createApplyBar(options: ApplyBarOptions): HTMLElement {
  const bar = E('div', {
    id: 'podkop-apply-bar',
    class: 'alert-message',
    role: 'status',
    'aria-live': 'polite',
    style: 'display: none',
  });
  const state: BarState = {
    changes: { podkop: 0, other: 0 },
    waiting: false,
  };
  // the status read when the page loaded, for an apply whose own read fails
  let known: Podkop.GetStatus | null = null;
  // this page asked an apply: LuCI reloads it, and the next page shows the result
  let applying = false;
  let following = false;
  let changesAsked = 0;

  const button = (
    label: string,
    classes: string,
    action: (event: Event) => unknown,
  ) => {
    const element = E('button', {
      class: 'btn cbi-button ' + classes,
      type: 'button',
    });
    element.textContent = label;
    element.addEventListener('click', (event) => {
      element.disabled = true;
      Promise.resolve()
        .then(() => action(event))
        .catch((err) => logger.warn('[APPLY]', err))
        .finally(() => {
          element.disabled = false;
        });
    });
    return element;
  };

  const actions: Record<BarButton, () => HTMLElement> = {
    apply: () =>
      button(
        luciText('Save & Apply'),
        'cbi-button-apply important',
        options.saveApply,
      ),
    show: () =>
      button(_('Show'), 'cbi-button-neutral', () =>
        uci.changes().then((changes) => {
          const changesUI = luciChanges();
          changesUI?.renderChangeIndicator(changes);
          changesUI?.displayChanges();
        }),
      ),
    revert: () =>
      button(luciText('Revert'), 'cbi-button-reset', () =>
        luciChanges()?.revert(),
      ),
    dismiss: () =>
      button(luciText('Dismiss'), 'cbi-button-neutral', () => {
        state.result = undefined;
        writeRecord(null);
        render();
      }),
  };

  const render = () => {
    const view = barView(state);
    bar.className = ['alert-message', BAR_CLASSES[view.kind]].join(' ').trim();
    bar.setAttribute('data-kind', view.kind);
    bar.style.display = view.kind === 'none' ? 'none' : '';
    while (bar.firstChild) bar.removeChild(bar.firstChild);
    if (view.kind === 'none') return;
    const text = E('p', { class: 'podkop-apply-text' });
    text.textContent = view.text;
    bar.appendChild(text);
    if (view.buttons.length) {
      bar.appendChild(
        E(
          'div',
          { class: 'podkop-apply-actions' },
          view.buttons.map((name) => actions[name]()),
        ),
      );
    }
  };

  const refreshChanges = () => {
    const asked = ++changesAsked;
    Promise.resolve(uci.changes())
      .then((changes) => {
        if (asked !== changesAsked) return;
        state.changes = countChanges(changes);
        render();
      })
      .catch((err) => logger.warn('[APPLY]', 'uci changes:', err));
  };

  const show = (record: ApplyRecord, result: ApplyResult) => {
    state.waiting = false;
    state.result = result;
    // the page that asked the apply is reloaded by LuCI: the next one shows it once more
    writeRecord(applying ? { ...record, result } : null);
    render();
    // an apply that failed or was rolled back leaves its changes staged: they come first
    refreshChanges();
  };

  // follow asks the backend until the apply of the record has come to something
  const follow = async (record: ApplyRecord) => {
    if (following) return;
    following = true;
    try {
      for (;;) {
        let status: Podkop.GetStatus | null = null;
        try {
          status = await readStatus();
        } catch (err) {
          logger.warn('[APPLY]', 'get_status:', err);
        }
        const result = judge(record, status, Date.now());
        if (result) {
          show(record, result);
          return;
        }
        await new Promise((resolve) => setTimeout(resolve, APPLY_POLL_MS));
      }
    } finally {
      following = false;
    }
  };

  const before = async () => {
    const changesUI = luciChanges();
    // LuCI's own first words of an apply, at once: the reads take a moment
    changesUI?.displayStatus?.(
      'notice spinning',
      E('p', {}, [luciText('Starting configuration apply…')]),
    );
    let changes: unknown = null;
    let fresh: Podkop.GetStatus | null = null;
    try {
      [changes, fresh] = await withTimeout(
        Promise.all([
          Promise.resolve(uci.changes()).catch(() => null),
          readStatus().catch(() => null),
        ]),
        BEFORE_MS,
        'apply bar: the reads before an apply',
      );
    } catch (err) {
      logger.warn('[APPLY]', err);
    }
    // no change of podkop: the backend is not asked to apply anything
    if (changes && countChanges(changes).podkop === 0) return;
    const record = newRecord(fresh, known, Date.now());
    if (!record) return;
    applying = true;
    writeRecord(record);
    state.waiting = true;
    state.result = undefined;
    render();
    // when LuCI does not reload the page (the apply failed, or was rolled back) this page
    // tells what came of it
    follow(record);
  };

  const changesUI = luciChanges();
  if (changesUI) wrapApply(changesUI, before);
  document.addEventListener('uci-loaded', refreshChanges);
  refreshChanges();

  const record = readRecord();
  if (record?.result) {
    show(record, record.result);
  } else if (record) {
    state.waiting = true;
    render();
    follow(record);
  }
  readStatus()
    .then((status) => {
      known = status;
    })
    .catch(() => undefined);

  return bar;
}
