import { CustomPodkopMethods, PodkopShellMethods } from '../methods';
import type { Podkop } from '../types';
import { detectPasted, unwrapSubscription } from '../sources';
import {
  AGENT_PRESETS,
  listRequest,
  presetName,
} from '../../validators/validateRequestHeader';
import { validateProxyUrl } from '../../validators/validateProxyUrl';
import { DNS_SERVER_OPTIONS } from '../../constants';
import {
  defaultSettings,
  describe,
  importPasted,
  listedServers,
  type ImportDeps,
  type ImportOutcome,
  type ListedServer,
  type NewSource,
  type SourceKind,
  type SourceSettings,
  type WizardSource,
} from './importer';
import { createRouting } from './routing';
import { createDns } from './dns';
import { buildConfig, type WizardConfig } from './config';

export { styles } from './styles';

// The setup wizard: a window of its own over the page (not a window of LuCI: no form of LuCI is
// behind it). Step 1 holds its sources in the memory of the page; nothing is written to the
// router until the last step.

const ICONS: Record<string, string> = {
  paste:
    '<path d="M11 14h10"/><path d="M16 4h2a2 2 0 0 1 2 2v1.344"/><path d="m17 18 4-4-4-4"/><path d="M8 4H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 1.793-1.113"/><rect x="8" y="2" width="8" height="4" rx="1"/>',
  rss: '<path d="M4 11a9 9 0 0 1 9 9"/><path d="M4 4a16 16 0 0 1 16 16"/><circle cx="5" cy="19" r="1"/>',
  link: '<path d="M9 17H7A5 5 0 0 1 7 7h2"/><path d="M15 7h2a5 5 0 1 1 0 10h-2"/><line x1="8" x2="16" y1="12" y2="12"/>',
  braces:
    '<path d="M8 3H7a2 2 0 0 0-2 2v5a2 2 0 0 1-2 2 2 2 0 0 1 2 2v5c0 1.1.9 2 2 2h1"/><path d="M16 21h1a2 2 0 0 0 2-2v-5c0-1.1.9-2 2-2a2 2 0 0 1-2-2V5a2 2 0 0 0-2-2h-1"/>',
  trash:
    '<path d="M3 6h18"/><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"/><path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/><line x1="10" x2="10" y1="11" y2="17"/><line x1="14" x2="14" y1="11" y2="17"/>',
  settings:
    '<path d="M14 17H5"/><path d="M19 7h-9"/><circle cx="17" cy="17" r="3"/><circle cx="7" cy="7" r="3"/>',
  plus: '<path d="M5 12h14"/><path d="M12 5v14"/>',
  x: '<path d="M18 6 6 18"/><path d="m6 6 12 12"/>',
  ok: '<circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/>',
  warn: '<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3"/><path d="M12 9v4"/><path d="M12 17h.01"/>',
  bad: '<circle cx="12" cy="12" r="10"/><path d="m15 9-6 6"/><path d="m9 9 6 6"/>',
  loader: '<path d="M21 12a9 9 0 1 1-6.219-8.56"/>',
  eye: '<path d="M2.062 12.348a1 1 0 0 1 0-.696 10.75 10.75 0 0 1 19.876 0 1 1 0 0 1 0 .696 10.75 10.75 0 0 1-19.876 0"/><circle cx="12" cy="12" r="3"/>',
  eyeOff:
    '<path d="M10.733 5.076a10.744 10.744 0 0 1 11.205 6.575 1 1 0 0 1 0 .696 10.747 10.747 0 0 1-1.444 2.49"/><path d="M14.084 14.158a3 3 0 0 1-4.242-4.242"/><path d="M17.479 17.499a10.75 10.75 0 0 1-15.417-5.151 1 1 0 0 1 0-.696 10.75 10.75 0 0 1 4.446-5.143"/><path d="m2 2 20 20"/>',
  chevron: '<path d="m6 9 6 6 6-6"/>',
  back: '<path d="m12 19-7-7 7-7"/><path d="M19 12H5"/>',
  network:
    '<rect x="16" y="16" width="6" height="6" rx="1"/><rect x="2" y="16" width="6" height="6" rx="1"/><rect x="9" y="2" width="6" height="6" rx="1"/><path d="M5 16v-3a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1v3"/><path d="M12 12V8"/>',
  check: '<path d="M20 6 9 17l-5-5"/>',
  grip: '<circle cx="9" cy="12" r="1"/><circle cx="9" cy="5" r="1"/><circle cx="9" cy="19" r="1"/><circle cx="15" cy="12" r="1"/><circle cx="15" cy="5" r="1"/><circle cx="15" cy="19" r="1"/>',
  inbox:
    '<polyline points="22 12 16 12 14 15 10 15 8 12 2 12"/><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/>',
};

function icon(name: string, size = 16): HTMLElement {
  const span = document.createElement('span');
  span.className = 'pdk-wizard__icon pdk-wizard__icon--' + name;
  span.innerHTML =
    '<svg xmlns="http://www.w3.org/2000/svg" width="' +
    size +
    '" height="' +
    size +
    '" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
    ICONS[name] +
    '</svg>';
  return span;
}

type Child = Node | string | null | undefined | false;

function h(
  tag: string,
  attrs: Record<string, string> = {},
  children: Child[] = [],
): HTMLElement {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) el.setAttribute(key, value);
  for (const child of children) {
    if (child === null || child === undefined || child === false) continue;
    el.append(child);
  }
  return el;
}

const SCHEMES = [
  'https:// подписка',
  'vless://',
  'ss://',
  'trojan://',
  'hy2://',
  'tuic://',
  'socks://',
];

const STEPS = ['Источники', 'Маршрутизация', 'DNS'];

// The manual form: the settings of one source as the package has them, for a new source or for
// one of the list (editId). The values are kept as they are typed; the window is drawn again
// only when the form changes its shape.
interface ManualForm {
  kind: SourceKind;
  editId: number | null;
  url: string;
  // whether the address is shown: an address typed now is, one that came filled is covered
  showUrl: boolean;
  links: string;
  json: string;
  iface: string;
  settings: SourceSettings;
  // the servers of a subscription of the list, as they were imported
  list: ListedServer[];
  listOpen: boolean;
  provider: string;
  usable: number;
  // the address and the request the list above was asked with, and whether it brought servers:
  // a form that still asks the same is kept without another download
  loadedKey: string;
  loadedOk: boolean;
  // the list is being asked again, for a request changed in the form
  loading: boolean;
  busy: boolean;
  // what stops the form: a line, or lines by their number
  error: string;
  details: [string, string][];
}

// a device of the router an interface source may name
export interface OutDevice {
  name: string;
  ipv4: boolean;
}

// what the wizard needs of the page around it: set by the view, which has LuCI's network
export interface WizardEnv {
  outDevices?: () => Promise<OutDevice[]>;
  // the DNS servers of the provider the router knows now
  providerDns?: () => Promise<string[]>;
  // Writes the config the wizard made and applies it. It is given the names the file has, so
  // that the new sections get free ones; the old sources, rules and DNS servers are replaced.
  save?: (build: (taken: string[]) => WizardConfig) => Promise<void>;
}

let env: WizardEnv = {};
let devices: OutDevice[] = [];

export function setWizardEnv(next: WizardEnv) {
  env = next;
}

interface State {
  sources: WizardSource[];
  outcome: ImportOutcome | null;
  busy: boolean;
  // what stands in the field while the router is asked about it
  pending: string;
  nextId: number;
  manual: ManualForm | null;
  // the step shown: 1 the sources, 2 the routing, 3 the DNS
  step: number;
  // the config is being written
  saving: boolean;
  // the config is written, podkop is starting
  started: boolean;
}

const state: State = {
  sources: [],
  outcome: null,
  busy: false,
  pending: '',
  nextId: 1,
  manual: null,
  step: 1,
  saving: false,
  started: false,
};

let root: HTMLElement | null = null;

const LOAD_BUDGET_MS = 60000;
const LOAD_POLL_MS = 700;

const deps: ImportDeps = {
  async checkLinks(links) {
    const answer = await PodkopShellMethods.checkLinks(links);
    return answer.success && Array.isArray(answer.data) ? answer.data : null;
  },
  // the list as the router gets it, by the job it runs: start, then ask until it ends
  async loadSubscription(url, request, control) {
    const started = await PodkopShellMethods.subscriptionLoadStart(
      url,
      request,
    );
    if (!started.success || !started.data?.id) return null;
    let job: Podkop.LoadJob = started.data;
    const until = Date.now() + LOAD_BUDGET_MS;
    while (job.state === 'running' && Date.now() < until) {
      if (control?.cancelled) {
        PodkopShellMethods.subscriptionLoadCancel(job.id);
        return null;
      }
      await new Promise((resolve) => setTimeout(resolve, LOAD_POLL_MS));
      const next = await PodkopShellMethods.subscriptionLoadState(job.id);
      if (!next.success || !next.data) return null;
      job = next.data;
    }
    if (job.state === 'running') {
      PodkopShellMethods.subscriptionLoadCancel(job.id);
      return null;
    }
    return job.preview ?? null;
  },
};

async function take(text: string) {
  if (state.busy || !text.trim()) return;
  state.busy = true;
  state.pending = text.trim().split(/\s+/)[0].slice(0, 60);
  state.outcome = null;
  draw();
  let outcome: ImportOutcome | null = null;
  try {
    outcome = await importPasted(text, state.sources, deps);
  } catch (_e) {
    outcome = {
      tone: 'bad',
      title: 'Роутер не ответил',
      detail: 'Ничего не импортировано.',
    };
  }
  state.busy = false;
  state.pending = '';
  state.outcome = outcome;
  if (outcome?.source) {
    state.sources.push({ ...outcome.source, id: state.nextId++ });
  }
  draw();
}

function remove(id: number) {
  state.sources = state.sources.filter((item) => item.id !== id);
  state.outcome = null;
  draw();
}

function renderSteps(): HTMLElement {
  const row = h('div', { class: 'pdk-wizard__steps' });
  STEPS.forEach((label, index) => {
    if (index) row.append(h('div', { class: 'pdk-wizard__steps-line' }));
    row.append(
      h(
        'div',
        {
          class:
            'pdk-wizard__step' +
            (index === state.step - 1 ? ' pdk-wizard__step--active' : '') +
            (index < state.step - 1 ? ' pdk-wizard__step--done' : ''),
        },
        [
          h('span', { class: 'pdk-wizard__step-number' }, [
            index < state.step - 1 ? icon('check', 14) : String(index + 1),
          ]),
          h('span', { class: 'pdk-wizard__step-label' }, [label]),
        ],
      ),
    );
  });
  return row;
}

function renderField(): HTMLElement {
  const input = h('input', {
    class: 'pdk-wizard__input',
    type: 'text',
    placeholder: state.busy
      ? 'Импортируем ' + state.pending + '…'
      : 'Вставьте подписку или ссылки на серверы',
    autocomplete: 'off',
    spellcheck: 'false',
    'aria-label': 'Подписка или ссылки на серверы',
  }) as HTMLInputElement;
  input.disabled = state.busy;
  // a paste is imported at once and never stays in the field, taken or not
  input.addEventListener('paste', (event) => {
    event.preventDefault();
    take(event.clipboardData?.getData('text') ?? '');
  });
  // what was typed by hand goes the same way at Enter
  input.addEventListener('keydown', (event) => {
    if (event.key !== 'Enter') return;
    event.preventDefault();
    const value = input.value;
    input.value = '';
    take(value);
  });
  return h('div', { class: 'pdk-wizard__import' }, [
    h(
      'label',
      {
        class:
          'pdk-wizard__field' + (state.busy ? ' pdk-wizard__field--busy' : ''),
      },
      [
        h('span', { class: 'pdk-wizard__field-icon' }, [
          icon(state.busy ? 'loader' : 'paste', 17),
        ]),
        input,
      ],
    ),
    h('div', { class: 'pdk-wizard__schemes' }, [
      h('span', { class: 'pdk-wizard__schemes-label' }, ['Подходит']),
      ...SCHEMES.map((item) =>
        h('span', { class: 'pdk-wizard__scheme' }, [item]),
      ),
    ]),
  ]);
}

function renderOutcome(): HTMLElement | null {
  const outcome = state.outcome;
  if (!outcome) return null;
  const setup = outcome.setup
    ? h('button', { class: 'pdk-wizard__alert-button', type: 'button' }, [
        'Настроить подписку',
      ])
    : null;
  setup?.addEventListener('click', () => {
    const failed = outcome.setup;
    if (!failed) return;
    const form = newForm('subscription');
    form.url = failed.url;
    form.showUrl = false;
    form.loadedKey = subscriptionAsk(form)?.key ?? '';
    form.error = 'Не удалось получить подписку';
    openManual(form);
  });
  return h(
    'div',
    {
      class: 'pdk-wizard__alert pdk-wizard__alert--' + outcome.tone,
      role: 'status',
    },
    [
      icon(outcome.tone, 16),
      h('div', { class: 'pdk-wizard__alert-text' }, [
        h('div', { class: 'pdk-wizard__alert-title' }, [outcome.title]),
        outcome.detail
          ? h('div', { class: 'pdk-wizard__alert-detail' }, [outcome.detail])
          : null,
      ]),
      setup,
    ],
  );
}

function renderList(): HTMLElement {
  const manual = h(
    'button',
    { class: 'pdk-wizard__ghost-button', type: 'button' },
    [icon('plus', 14), 'Добавить вручную'],
  );
  manual.addEventListener('click', () => openManual(newForm('subscription')));
  const head = h('div', { class: 'pdk-wizard__list-head' }, [
    h('div', { class: 'pdk-wizard__list-title' }, [
      'Добавлено',
      state.sources.length
        ? h('span', { class: 'pdk-wizard__count' }, [
            String(state.sources.length),
          ])
        : null,
    ]),
    manual,
  ]);
  if (!state.sources.length) {
    return h('div', { class: 'pdk-wizard__sources' }, [
      head,
      h('div', { class: 'pdk-wizard__empty' }, [
        icon('inbox', 24),
        h('div', {}, [
          'Пока пусто. Вставьте ссылку в поле выше или добавьте источник вручную',
        ]),
      ]),
    ]);
  }
  const rows = state.sources.map((item) => {
    const setup = h(
      'button',
      {
        class: 'pdk-wizard__icon-button',
        type: 'button',
        title: 'Настроить',
        'aria-label': 'Настроить',
      },
      [icon('settings', 16)],
    );
    setup.addEventListener('click', () => openManual(formOf(item)));
    const del = h(
      'button',
      {
        class: 'pdk-wizard__icon-button',
        type: 'button',
        title: 'Удалить',
        'aria-label': 'Удалить',
      },
      [icon('trash', 16)],
    );
    del.addEventListener('click', () => remove(item.id));
    const kindIcon = KIND_ICON[item.kind];
    const text = describe(item);
    return h('div', { class: 'pdk-wizard__source' }, [
      h(
        'span',
        {
          class:
            'pdk-wizard__source-kind pdk-wizard__source-kind--' + item.kind,
        },
        [icon(kindIcon, 18)],
      ),
      h('div', { class: 'pdk-wizard__source-text' }, [
        h('div', { class: 'pdk-wizard__source-title' }, [text.title]),
        h('div', { class: 'pdk-wizard__source-subtitle' }, [text.subtitle]),
      ]),
      setup,
      del,
    ]);
  });
  return h('div', { class: 'pdk-wizard__sources' }, [head, ...rows]);
}

const KIND_ICON: Record<SourceKind, string> = {
  subscription: 'rss',
  links: 'link',
  json: 'braces',
  interface: 'network',
};

const KINDS: [SourceKind, string, string][] = [
  ['subscription', 'Подписка', 'Адрес от провайдера'],
  ['links', 'Ссылки', 'vless://, ss://, trojan://…'],
  ['json', 'Outbound JSON', 'Конфигурация sing-box'],
  ['interface', 'Интерфейс', 'Туннель, второй WAN'],
];

const INTERVALS: [string, string][] = [
  ['auto', 'Автоматически'],
  ['20m', 'Каждые 20 минут'],
  ['1h', 'Каждый час'],
  ['3h', 'Каждые 3 часа'],
  ['6h', 'Каждые 6 часов'],
  ['9h', 'Каждые 9 часов'],
  ['12h', 'Каждые 12 часов'],
  ['1d', 'Раз в сутки'],
];

const DNS_TYPES: [string, string][] = [
  ['udp', 'UDP (незащищённый DNS)'],
  ['dot', 'DNS через TLS (DoT)'],
  ['doh', 'DNS через HTTPS (DoH)'],
];

function newForm(kind: SourceKind): ManualForm {
  return {
    kind,
    editId: null,
    url: '',
    showUrl: true,
    links: '',
    json: '',
    iface: '',
    settings: defaultSettings(),
    list: [],
    listOpen: false,
    provider: '',
    usable: 0,
    loadedKey: '',
    loadedOk: false,
    loading: false,
    busy: false,
    error: '',
    details: [],
  };
}

function formOf(source: WizardSource): ManualForm {
  const form = formFrom(source);
  if (source.kind === 'subscription') {
    form.provider = source.provider ?? '';
    form.usable = source.servers ?? 0;
    form.loadedKey = subscriptionAsk(form)?.key ?? '';
    form.loadedOk = form.usable > 0;
  }
  return form;
}

function formFrom(source: WizardSource): ManualForm {
  return {
    ...newForm(source.kind),
    editId: source.id,
    url: source.url ?? '',
    showUrl: false,
    links: (source.links ?? []).join('\n'),
    json: source.json ?? '',
    iface: source.iface ?? '',
    settings: { ...source.settings },
    list: source.list ?? [],
  };
}

// what the form of a subscription asks the router: null while the form cannot ask yet
function subscriptionAsk(
  form: ManualForm,
): { url: string; request: Podkop.ListRequest; key: string } | null {
  const typed = form.url.trim();
  const url = unwrapSubscription(typed)?.url ?? typed;
  if (!/^https?:\/\/\S+$/i.test(url)) return null;
  if (
    form.settings.agentPreset === 'custom' &&
    !form.settings.userAgent.trim()
  ) {
    return null;
  }
  const request = listRequest(
    form.settings.userAgent,
    form.settings.headers,
    form.settings.agentPreset,
  );
  return { url, request, key: JSON.stringify([url, request]) };
}

function fresh(form: ManualForm): boolean {
  const ask = subscriptionAsk(form);
  return !!ask && form.loadedOk && ask.key === form.loadedKey;
}

// what a download brought goes to the form: its servers, or why there are none
function applyPreview(
  form: ManualForm,
  key: string,
  preview: Podkop.SubscriptionPreview | null,
) {
  form.list = listedServers(preview);
  form.usable = form.list.filter((item) => !item.reason).length;
  form.provider = preview?.provider?.title?.trim() || '';
  form.loadedKey = key;
  form.loadedOk = form.usable > 0;
  form.listOpen = false;
  if (form.loadedOk) {
    form.error = '';
    form.details = [];
  } else {
    form.error = 'Не удалось получить подписку';
    form.details = [];
  }
}

let loadControl: { cancelled: boolean } | null = null;

// The servers shown follow the request of the form: when the address, the app the list is asked
// as or the headers change, the list is asked again and the block is drawn in place (the rest of
// the form, and what is being typed in it, stays as it is).
async function refreshServers(form: ManualForm) {
  if (form.kind !== 'subscription' || form.busy) return;
  const ask = subscriptionAsk(form);
  if (!ask || ask.key === form.loadedKey) return;
  if (loadControl) loadControl.cancelled = true;
  const control = { cancelled: false };
  loadControl = control;
  form.loading = true;
  form.error = '';
  form.details = [];
  patchPreview(form);
  let preview: Podkop.SubscriptionPreview | null = null;
  try {
    preview = await deps.loadSubscription(ask.url, ask.request, control);
  } catch (_e) {
    preview = null;
  }
  if (control.cancelled || state.manual !== form) return;
  form.loading = false;
  applyPreview(form, ask.key, preview);
  patchPreview(form);
}

function syncAction(form: ManualForm) {
  const next = root?.querySelector<HTMLButtonElement>('.pdk-wizard__next');
  if (!next) return;
  next.textContent = manualAction(form);
  next.disabled = form.busy;
}

function patchPreview(form: ManualForm) {
  root?.querySelector('.pdk-wizard__preview')?.replaceWith(renderPreview(form));
  syncAction(form);
}

function openManual(form: ManualForm) {
  state.manual = form;
  state.outcome = null;
  draw();
  if (form.kind === 'interface') loadDevices();
}

function closeManual() {
  if (loadControl) loadControl.cancelled = true;
  state.manual = null;
  draw();
}

async function loadDevices() {
  if (!env.outDevices) return;
  try {
    devices = await env.outDevices();
  } catch (_e) {
    devices = [];
  }
  if (state.manual?.kind === 'interface') draw();
}

function splitLines(text: string): string[] {
  return text
    .split(/\s+/)
    .map((line) => line.trim())
    .filter(Boolean);
}

function keep(form: ManualForm, source: NewSource, ok: string) {
  if (form.editId !== null) {
    state.sources = state.sources.map((item) =>
      item.id === form.editId ? { ...source, id: item.id } : item,
    );
  } else {
    state.sources.push({ ...source, id: state.nextId++ });
  }
  state.manual = null;
  state.outcome = { tone: 'ok', title: ok, detail: describe(source).title };
  draw();
}

async function submitManual() {
  const form = state.manual;
  if (!form || form.busy) return;
  form.error = '';
  form.details = [];
  const done = form.editId !== null ? 'Источник изменён' : 'Источник добавлен';

  if (form.kind === 'subscription') {
    const typed = form.url.trim();
    const url = unwrapSubscription(typed)?.url ?? typed;
    if (!/^https?:\/\/\S+$/i.test(url)) {
      form.error = 'Нужен адрес подписки: https://…';
      return draw();
    }
    const ask = subscriptionAsk(form);
    if (!ask) {
      form.error = 'Для «Другой User-Agent» впишите его название.';
      return draw();
    }
    // the list shown was asked with this very request: nothing more to download
    if (!fresh(form)) {
      if (loadControl) loadControl.cancelled = true;
      form.loading = false;
      form.busy = true;
      draw();
      let preview: Podkop.SubscriptionPreview | null = null;
      try {
        preview = await deps.loadSubscription(ask.url, ask.request);
      } catch (_e) {
        preview = null;
      }
      form.busy = false;
      applyPreview(form, ask.key, preview);
      if (!form.loadedOk) {
        return draw();
      }
    }
    return keep(
      form,
      {
        kind: 'subscription',
        url: ask.url,
        settings: { ...form.settings },
        provider: form.provider,
        servers: form.usable,
        list: form.list,
      },
      done,
    );
  }

  if (form.kind === 'links') {
    const links = splitLines(form.links);
    if (!links.length) {
      form.error = 'Впишите хотя бы одну ссылку на сервер.';
      return draw();
    }
    form.busy = true;
    draw();
    const checks = await deps.checkLinks(links);
    form.busy = false;
    const problems: [string, string][] = [];
    links.forEach((link, index) => {
      const local = validateProxyUrl(link);
      const remote = checks ? checks[index] : { ok: true };
      if (local.valid && remote?.ok) return;
      problems.push([
        'Строка ' + (index + 1),
        !local.valid ? local.message : (remote?.error ?? 'не подходит'),
      ]);
    });
    if (problems.length) {
      form.error = 'Не все ссылки подходят. Исправьте или уберите эти строки.';
      form.details = problems;
      return draw();
    }
    return keep(
      form,
      { kind: 'links', links, settings: { ...form.settings } },
      done,
    );
  }

  if (form.kind === 'json') {
    const found = detectPasted(form.json);
    if (found.kind !== 'json') {
      form.error =
        found.kind === 'error'
          ? [found.title, found.note].filter(Boolean).join('. ')
          : 'Ожидается один outbound sing-box: {"type": "vless", …}';
      return draw();
    }
    return keep(
      form,
      { kind: 'json', json: form.json.trim(), settings: { ...form.settings } },
      done,
    );
  }

  if (form.settings.resolver && !form.settings.dnsServer.trim()) {
    form.error = 'Для резолвера доменов нужен адрес DNS-сервера.';
    return draw();
  }
  return keep(
    form,
    {
      kind: 'interface',
      iface: form.iface.trim(),
      settings: { ...form.settings },
    },
    done,
  );
}

// the controls of the form: each writes what is typed to the form at once
function field(label: string, control: Node, help?: string): HTMLElement {
  return h('label', { class: 'pdk-wizard__control' }, [
    h('span', { class: 'pdk-wizard__control-label' }, [label]),
    control,
    help ? h('span', { class: 'pdk-wizard__control-help' }, [help]) : null,
  ]);
}

function textInput(
  value: string,
  onInput: (value: string) => void,
  attrs: Record<string, string> = {},
): HTMLInputElement {
  const input = h('input', {
    class: 'pdk-wizard__text',
    type: 'text',
    autocomplete: 'off',
    spellcheck: 'false',
    ...attrs,
  }) as HTMLInputElement;
  input.value = value;
  input.addEventListener('input', () => onInput(input.value));
  return input;
}

function textArea(
  value: string,
  onInput: (value: string) => void,
  attrs: Record<string, string> = {},
): HTMLTextAreaElement {
  const area = h('textarea', {
    class: 'pdk-wizard__text pdk-wizard__text--area',
    spellcheck: 'false',
    ...attrs,
  }) as HTMLTextAreaElement;
  area.value = value;
  area.addEventListener('input', () => onInput(area.value));
  return area;
}

// A field of a secret (the address of a subscription): covered, with an eye that shows it. The
// package covers the same field. The eye changes the field in place: what is typed stays.
function secretInput(
  value: string,
  shown: boolean,
  onInput: (value: string) => void,
  onToggle: (shown: boolean) => void,
  attrs: Record<string, string> = {},
): HTMLElement {
  const input = textInput(value, onInput, {
    autocomplete: 'new-password',
    ...attrs,
  });
  const eye = h('button', { class: 'pdk-wizard__eye', type: 'button' });
  let visible = shown;
  const apply = () => {
    input.type = visible ? 'text' : 'password';
    const label = visible ? 'Скрыть адрес' : 'Показать адрес';
    eye.title = label;
    eye.setAttribute('aria-label', label);
    eye.setAttribute('aria-pressed', String(visible));
    eye.replaceChildren(icon(visible ? 'eyeOff' : 'eye', 16));
  };
  eye.addEventListener('click', () => {
    visible = !visible;
    onToggle(visible);
    apply();
    input.focus();
  });
  apply();
  return h('span', { class: 'pdk-wizard__secret' }, [input, eye]);
}

// a select drawn as the text fields are: the browser's own arrow and inset are taken off, the
// arrow is the wizard's
function select(
  value: string,
  options: [string, string][],
  onChange: (value: string) => void,
): HTMLElement {
  const el = h('select', { class: 'pdk-wizard__text' }) as HTMLSelectElement;
  for (const [key, label] of options) {
    const option = h('option', { value: key }, [label]) as HTMLOptionElement;
    option.selected = key === value;
    el.append(option);
  }
  el.addEventListener('change', () => onChange(el.value));
  return h('span', { class: 'pdk-wizard__select' }, [el, icon('chevron', 16)]);
}

function checkbox(
  checked: boolean,
  label: string,
  help: string,
  onChange: (checked: boolean) => void,
): HTMLElement {
  const box = h('input', { type: 'checkbox' }) as HTMLInputElement;
  box.checked = checked;
  box.addEventListener('change', () => onChange(box.checked));
  return h('label', { class: 'pdk-wizard__check' }, [
    box,
    h('span', { class: 'pdk-wizard__check-text' }, [
      h('span', { class: 'pdk-wizard__check-label' }, [label]),
      help ? h('span', { class: 'pdk-wizard__control-help' }, [help]) : null,
    ]),
  ]);
}

function row(children: HTMLElement[]): HTMLElement {
  return h('div', { class: 'pdk-wizard__row' }, children);
}

// a field of the request of a subscription: when it is left changed, the servers are asked again
function again<T extends HTMLElement>(control: T, form: ManualForm): T {
  const input = control.matches('input, textarea')
    ? control
    : control.querySelector('input, textarea');
  input?.addEventListener('change', () => refreshServers(form));
  return control;
}

function renderKindFields(form: ManualForm): HTMLElement[] {
  const set = form.settings;
  switch (form.kind) {
    case 'subscription': {
      const presets: [string, string][] = AGENT_PRESETS.map((preset) => [
        preset,
        preset === 'custom' ? 'Другой User-Agent' : presetName(preset),
      ]);
      return [
        field(
          'Адрес подписки',
          again(
            secretInput(
              form.url,
              form.showUrl,
              (value) => {
                form.url = value;
                syncAction(form);
              },
              (shown) => (form.showUrl = shown),
              { placeholder: 'https://…' },
            ),
            form,
          ),
          'Адрес, который провайдер дал для приложений (часто /sub/… или /api/sub/…). Это секрет: podkop скрывает его там, где показывает настройки.',
        ),
        row([
          field(
            'Запрашивать как',
            select(set.agentPreset, presets, (value) => {
              set.agentPreset = value;
              draw();
              refreshServers(form);
            }),
            'Некоторые провайдеры отдают серверы только названным ими приложениям. HWID роутера остаётся его собственным.',
          ),
          field(
            'Интервал обновления',
            select(set.updateInterval, INTERVALS, (value) => {
              set.updateInterval = value;
            }),
            'Автоматически: как советует провайдер, иначе раз в день.',
          ),
        ]),
        set.agentPreset === 'custom'
          ? field(
              'User-Agent',
              again(
                textInput(
                  set.userAgent,
                  (value) => {
                    set.userAgent = value;
                    syncAction(form);
                  },
                  { placeholder: 'v2rayNG' },
                ),
                form,
              ),
              'Название приложения так, как его называет провайдер. Часто хватает одного названия, без версии.',
            )
          : null,
        field(
          'Дополнительные заголовки',
          again(
            textArea(
              set.headers,
              (value) => {
                set.headers = value;
                syncAction(form);
              },
              { placeholder: 'Authorization: Bearer …', rows: '2' },
            ),
            form,
          ),
          'Только если их требует провайдер: по одному в строке, в виде Имя: значение.',
        ),
      ].filter(Boolean) as HTMLElement[];
    }
    case 'links':
      return [
        field(
          'Ссылки на серверы',
          textArea(form.links, (value) => (form.links = value), {
            placeholder: 'vless://…',
            rows: '5',
          }),
          'По одной в строке: vless, trojan, ss, socks, http(s), hysteria2, tuic.',
        ),
        checkbox(
          set.udpOverTcp,
          'UDP через TCP',
          'Применимо для SOCKS и Shadowsocks прокси.',
          (value) => (set.udpOverTcp = value),
        ),
      ];
    case 'json':
      return [
        field(
          'Конфигурация исходящего соединения',
          textArea(form.json, (value) => (form.json = value), {
            placeholder: '{"type": "vless", "server": "…", …}',
            rows: '9',
          }),
          'Один outbound sing-box целиком. Список outbound-ов и вся конфигурация sing-box не подходят.',
        ),
      ];
    case 'interface': {
      const list = h(
        'datalist',
        { id: 'pdk-wizard-devices' },
        devices.map((device) =>
          h('option', { value: device.name }, [
            device.ipv4 ? '' : 'нет IPv4-адреса сейчас',
          ]),
        ),
      );
      const dns = h(
        'datalist',
        { id: 'pdk-wizard-dns' },
        Object.entries(DNS_SERVER_OPTIONS).map(([key, label]) =>
          h('option', { value: key }, [label]),
        ),
      );
      return [
        row([
          field(
            'Сетевой интерфейс',
            h('span', {}, [
              textInput(form.iface, (value) => (form.iface = value), {
                list: 'pdk-wizard-devices',
                placeholder: devices.length
                  ? devices.map((device) => device.name).join(', ')
                  : 'awg0',
              }),
              list,
            ]),
            'Туннель, модем или второй WAN. Туннеля, который сейчас не поднят, в списке нет: впишите его имя. Пусто: основной маршрут.',
          ),
          field(
            'Метка маршрутизации',
            textInput(set.routingMark, (value) => (set.routingMark = value), {
              placeholder: '0x10000',
            }),
            'Обычно не нужна.',
          ),
        ]),
        checkbox(
          set.resolver,
          'Резолвер доменов',
          'Настоящий IP сайта узнаётся через DNS-сервер по этому интерфейсу.',
          (value) => {
            set.resolver = value;
            draw();
          },
        ),
        set.resolver
          ? row([
              field(
                'Тип протокола DNS',
                select(
                  set.dnsType,
                  DNS_TYPES,
                  (value) => (set.dnsType = value),
                ),
              ),
              field(
                'DNS-сервер',
                h('span', {}, [
                  textInput(set.dnsServer, (value) => (set.dnsServer = value), {
                    list: 'pdk-wizard-dns',
                    placeholder: '1.1.1.1',
                  }),
                  dns,
                ]),
              ),
            ])
          : null,
      ].filter(Boolean) as HTMLElement[];
    }
  }
}

// The servers of a subscription as they were imported: all of them at once, as tags that wrap,
// with no list to scroll. A long list shows its head and a button that tells how many are left.
const SERVERS_SHOWN = 24;

function renderServers(form: ManualForm): HTMLElement {
  const list = form.list;
  const usable = list.filter((item) => !item.reason).length;
  const shown = form.listOpen ? list : list.slice(0, SERVERS_SHOWN);
  const more =
    list.length > shown.length
      ? h('button', { class: 'pdk-wizard__server-more', type: 'button' }, [
          'Показать ещё ' + (list.length - shown.length),
        ])
      : null;
  more?.addEventListener('click', () => {
    form.listOpen = true;
    draw();
  });
  return h('div', { class: 'pdk-wizard__servers' }, [
    h('div', { class: 'pdk-wizard__servers-head' }, [
      h('span', { class: 'pdk-wizard__servers-title' }, ['Серверы подписки']),
      h('span', { class: 'pdk-wizard__count' }, [String(usable)]),
      usable < list.length
        ? h('span', { class: 'pdk-wizard__control-help' }, [
            'ещё ' + (list.length - usable) + ' не подходят этой сборке',
          ])
        : null,
    ]),
    h('div', { class: 'pdk-wizard__servers-list' }, [
      ...shown.map((item) =>
        h(
          'span',
          {
            class:
              'pdk-wizard__server' +
              (item.reason ? ' pdk-wizard__server--off' : ''),
            title: item.reason || item.address,
          },
          [
            h('span', { class: 'pdk-wizard__server-name' }, [item.name]),
            h('span', { class: 'pdk-wizard__server-scheme' }, [item.scheme]),
          ],
        ),
      ),
      more,
    ]),
  ]);
}

// what stops the form, and for a subscription its servers: the part of the form that is drawn
// again when the list is asked anew
function renderPreview(form: ManualForm): HTMLElement {
  const problem = form.error
    ? h(
        'div',
        { class: 'pdk-wizard__alert pdk-wizard__alert--bad', role: 'alert' },
        [
          icon('bad', 16),
          h('div', { class: 'pdk-wizard__alert-text' }, [
            h('div', { class: 'pdk-wizard__alert-title' }, [form.error]),
            form.details.length
              ? h(
                  'dl',
                  { class: 'pdk-wizard__details' },
                  form.details.flatMap(([key, value]) => [
                    h('dt', {}, [key]),
                    h('dd', {}, [value]),
                  ]),
                )
              : null,
          ]),
        ],
      )
    : null;
  const loading = form.loading
    ? h('div', { class: 'pdk-wizard__loading', role: 'status' }, [
        icon('loader', 16),
        'Запрашиваем список серверов как ' +
          presetName(form.settings.agentPreset) +
          '…',
      ])
    : null;
  const servers =
    form.kind === 'subscription' && form.list.length
      ? renderServers(form)
      : null;
  return h(
    'div',
    {
      class:
        'pdk-wizard__preview' +
        (form.loading ? ' pdk-wizard__preview--loading' : ''),
    },
    [problem, loading, servers],
  );
}

function renderManual(form: ManualForm): HTMLElement {
  const back = h('button', { class: 'pdk-wizard__back', type: 'button' }, [
    icon('back', 14),
    'К списку источников',
  ]);
  back.addEventListener('click', closeManual);
  const editing = form.editId !== null;
  const kinds = h(
    'div',
    {
      class: 'pdk-wizard__kinds',
      role: 'radiogroup',
      'aria-label': 'Тип источника',
    },
    KINDS.map(([kind, label, note]) => {
      const tile = h(
        'button',
        {
          class:
            'pdk-wizard__kind' +
            (kind === form.kind ? ' pdk-wizard__kind--active' : ''),
          type: 'button',
          role: 'radio',
          'aria-checked': String(kind === form.kind),
        },
        [
          icon(KIND_ICON[kind], 18),
          h('span', { class: 'pdk-wizard__kind-label' }, [label]),
          h('span', { class: 'pdk-wizard__kind-note' }, [note]),
        ],
      );
      tile.addEventListener('click', () => {
        if (form.kind === kind) return;
        form.kind = kind;
        form.error = '';
        form.details = [];
        draw();
        if (kind === 'interface') loadDevices();
      });
      return tile;
    }),
  );
  const title = editing
    ? describe({
        kind: form.kind,
        url: form.url,
        links: splitLines(form.links),
        json: form.json,
        iface: form.iface,
        settings: form.settings,
      }).title
    : 'Добавить вручную';
  return h('div', { class: 'pdk-wizard__body' }, [
    back,
    h('div', { class: 'pdk-wizard__intro' }, [
      h('div', { class: 'pdk-wizard__heading' }, [title]),
      h('div', { class: 'pdk-wizard__lead' }, [
        editing
          ? 'Настройки этого источника — те же, что на вкладке «Серверы».'
          : 'Для случаев, когда вставки мало: особый запрос к провайдеру, интерфейс роутера, готовая конфигурация.',
      ]),
    ]),
    editing ? null : kinds,
    renderPreview(form),
    ...renderKindFields(form),
    h('div', { class: 'pdk-wizard__divider' }),
    field(
      'Название',
      textInput(form.settings.label, (value) => (form.settings.label = value), {
        placeholder: 'возьмётся из адреса, ссылки или интерфейса',
      }),
    ),
    checkbox(
      form.settings.skipDownloads,
      'Не использовать для загрузки списков и подписок',
      'Отметьте источник с малым лимитом трафика, тестовую подписку, туннель в закрытую сеть.',
      (value) => (form.settings.skipDownloads = value),
    ),
  ]);
}

function manualAction(form: ManualForm): string {
  if (form.busy) {
    return form.kind === 'subscription' ? 'Загружаем список…' : 'Проверяем…';
  }
  // a subscription whose list is on the screen for this request needs no download
  if (form.kind === 'subscription' && !fresh(form)) {
    return form.editId !== null
      ? 'Загрузить и сохранить'
      : 'Загрузить и добавить';
  }
  return form.editId !== null ? 'Сохранить' : 'Добавить в список';
}

const dns = createDns({
  h,
  icon,
  draw: () => draw(),
  back: () => {
    state.step = 2;
    draw();
  },
  providerDns: () =>
    env.providerDns ? env.providerDns() : Promise.resolve([]),
});

const START_BUDGET_MS = 90000;
const START_POLL_MS = 1500;

// The last step writes everything the wizard holds and shows the dashboard: the page is loaded
// again, so that every tab shows what was written.
async function save() {
  const stop = dns.problem();
  if (stop || !env.save) {
    dns.say(stop || 'Страница не может записать настройки: обновите её.');
    draw();
    return;
  }
  state.saving = true;
  dns.say('');
  draw();
  try {
    await env.save((taken) =>
      buildConfig(state.sources, routing.rules(), dns.value(), taken),
    );
  } catch (_e) {
    state.saving = false;
    dns.say('Не удалось сохранить настройки. Попробуйте ещё раз.');
    draw();
    return;
  }
  // The page is loaded again when podkop is up, so that the dashboard shows it at once: when
  // it runs, and, where a rule goes through servers, when its servers are there.
  state.started = true;
  draw();
  const wantsServers = routing
    .rules()
    .some((rule) => rule.enabled && rule.mode === 'servers');
  const until = Date.now() + START_BUDGET_MS;
  while (Date.now() < until) {
    await new Promise((resolve) => setTimeout(resolve, START_POLL_MS));
    try {
      const status = await PodkopShellMethods.getStatus();
      if (!status.success || !status.data?.running) continue;
      if (!wantsServers) break;
      const sections = await CustomPodkopMethods.getDashboardSections();
      if (sections.success && sections.data.some((g) => g.outbounds?.length)) {
        break;
      }
    } catch (_e) {
      // the backend restarts: asked again
    }
  }
  window.location.reload();
}

const routing = createRouting({
  h,
  icon,
  draw: () => draw(),
  sources: () => state.sources,
  kindIcon: KIND_ICON,
  back: () => {
    state.step = 1;
    draw();
  },
});

function draw() {
  if (!root) return;
  const close = h(
    'button',
    {
      class: 'pdk-wizard__close',
      type: 'button',
      title: 'Закрыть',
      'aria-label': 'Закрыть',
    },
    [icon('x', 18)],
  );
  close.addEventListener('click', closeWizard);
  const form = state.manual;
  const next = h('button', { class: 'pdk-wizard__next', type: 'button' }, [
    form
      ? manualAction(form)
      : state.step === 3
        ? state.started
          ? 'Podkop запускается…'
          : state.saving
            ? 'Сохраняется…'
            : 'Сохранить и запустить'
        : 'Далее',
  ]) as HTMLButtonElement;
  const routed = !form && state.step === 2;
  const named = !form && state.step === 3;
  if (routed) next.disabled = false;
  if (form) {
    next.disabled = form.busy;
    next.addEventListener('click', submitManual);
  } else if (routed) {
    next.addEventListener('click', () => {
      state.step = 3;
      dns.say('');
      draw();
    });
  } else if (named) {
    next.disabled = state.saving;
    next.addEventListener('click', save);
  } else {
    next.disabled = !state.sources.length || state.busy;
    next.addEventListener('click', () => {
      state.step = 2;
      state.outcome = null;
      routing.say('');
      draw();
    });
  }
  const body = form
    ? renderManual(form)
    : routed
      ? routing.render()
      : named
        ? dns.render()
        : h('div', { class: 'pdk-wizard__body' }, [
            h('div', { class: 'pdk-wizard__intro' }, [
              h('div', { class: 'pdk-wizard__heading' }, [
                'Добавьте подписку или серверы',
              ]),
              h('div', { class: 'pdk-wizard__lead' }, [
                'Вставьте подписку или ссылки на серверы — от провайдера или свои. Они импортируются сами. Вставлять можно несколько раз: всё попадёт в список ниже.',
              ]),
            ]),
            renderField(),
            renderOutcome(),
            renderList(),
          ]);
  const window = h(
    'div',
    {
      class: 'pdk-wizard__window',
      role: 'dialog',
      'aria-modal': 'true',
      'aria-label': 'Настройка Podkop',
    },
    [
      h('div', { class: 'pdk-wizard__head' }, [
        h('div', { class: 'pdk-wizard__title' }, ['Настройка Podkop']),
        close,
      ]),
      renderSteps(),
      body,
      h('div', { class: 'pdk-wizard__foot' }, [next]),
    ],
  );
  root.replaceChildren(window);
  if (routed) {
    next.disabled = !routing.ready();
    routing.afterDraw(root);
  }
  if (!state.busy && !state.manual && state.step === 1) {
    root.querySelector<HTMLInputElement>('.pdk-wizard__input')?.focus();
  }
}

function onKey(event: KeyboardEvent) {
  if (event.key !== 'Escape') return;
  if (state.manual) closeManual();
  else if (state.step === 2 && routing.escape()) return;
  else closeWizard();
}

export function openWizard() {
  if (root) return;
  root = h('div', { class: 'pdk-wizard', id: 'pdk-wizard' });
  root.addEventListener('mousedown', (event) => {
    if (event.target === root) closeWizard();
  });
  document.body.append(root);
  document.body.classList.add('pdk-wizard-open');
  document.addEventListener('keydown', onKey);
  draw();
}

export function closeWizard() {
  if (!root) return;
  document.removeEventListener('keydown', onKey);
  document.body.classList.remove('pdk-wizard-open');
  root.remove();
  root = null;
}
