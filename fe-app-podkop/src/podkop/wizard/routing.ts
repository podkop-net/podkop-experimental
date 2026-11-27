import {
  ALLOWED_WITH_RUSSIA_INSIDE,
  DOMAIN_LIST_OPTIONS,
  REGIONAL_OPTIONS,
} from '../../constants';
import { linkName, rowTakes } from '../sources';
import type { RuleValue } from './config';
import { describe, type SourceKind, type WizardSource } from './importer';

// Step 2 of the wizard: the rules of the package (config section) with their rows (config
// member), held in the memory of the page. A rule is what the package's rule is: lists of sites,
// an action, and for "through servers" a row per source with the package's filter. The order of
// the rules is their priority, as in the package: the upper one wins.

type Child = Node | string | null | undefined | false;

export interface RoutingKit {
  h(
    tag: string,
    attrs?: Record<string, string>,
    children?: Child[],
  ): HTMLElement;
  icon(name: string, size?: number): HTMLElement;
  draw(): void;
  sources(): WizardSource[];
  kindIcon: Record<SourceKind, string>;
  // back to the sources of step 1
  back(): void;
}

type Mode = 'servers' | 'direct' | 'block';

interface Row {
  sourceId: number;
  on: boolean;
  include: string[];
  exclude: string[];
  protocols: string[];
  open: boolean;
}

interface Rule {
  id: number;
  title: string;
  enabled: boolean;
  lists: string[];
  mode: Mode;
  rows: Row[];
  open: boolean;
  picker: boolean;
  search: string;
  // the lists Russia inside took the place of: they come back when it is taken away
  replaced: string[];
}

interface Server {
  name: string;
  scheme: string;
}

const LABELS: Record<string, string> = DOMAIN_LIST_OPTIONS;

// what Russia inside is made of: its eight lists and the three services whose domains it has
const DEFAULT_LISTS = [
  'geoblock',
  'block',
  'porn',
  'news',
  'anime',
  'youtube',
  'hdrezka',
  'tiktok',
  'meta',
  'twitter',
  'discord',
  'telegram',
];
const ASN_LISTS = ['hetzner', 'ovh', 'digitalocean', 'cloudfront'];
const SITE_LISTS = [
  ...DEFAULT_LISTS,
  ...Object.keys(LABELS).filter(
    (id) =>
      !DEFAULT_LISTS.includes(id) &&
      !ASN_LISTS.includes(id) &&
      !REGIONAL_OPTIONS.includes(id),
  ),
];

// what a rule does with its sites: the three actions of the package's rule
const MODES: [Mode, string, string][] = [
  ['servers', 'Проксировать', 'Через серверы'],
  ['direct', 'Напрямую', 'Мимо серверов'],
  ['block', 'Блокировать', 'Не открывать'],
];

const LISTS_SHOWN = 4;

export function createRouting(kit: RoutingKit) {
  const { h, icon } = kit;
  let rules: Rule[] = [];
  let nextId = 1;
  let focusKey = '';
  let notice = '';
  let started = false;
  let sheetScroll = 0;

  function serversOf(source: WizardSource): Server[] {
    if (source.kind === 'subscription') {
      return (source.list ?? [])
        .filter((item) => !item.reason)
        .map((item) => ({ name: item.name, scheme: item.scheme }));
    }
    if (source.kind === 'links') {
      return (source.links ?? []).map((link, index) => ({
        name: linkName(link) || 'сервер ' + (index + 1),
        scheme: link.slice(0, Math.max(0, link.indexOf('://'))),
      }));
    }
    return [];
  }

  // the package applies a row's filter to a subscription and to a source of several servers
  function filtered(source: WizardSource): boolean {
    return source.kind === 'subscription' || serversOf(source).length > 1;
  }

  function taken(source: WizardSource, row: Row): Server[] {
    return serversOf(source).filter(
      (server) =>
        rowTakes(server.name, row.include, row.exclude) &&
        (!row.protocols.length || row.protocols.includes(server.scheme)),
    );
  }

  // how many servers a row gives its rule
  function gives(source: WizardSource, row: Row): number {
    if (!row.on) return 0;
    return filtered(source) ? taken(source, row).length : 1;
  }

  function newRow(sourceId: number, on: boolean): Row {
    return {
      sourceId,
      on,
      include: [],
      exclude: [],
      protocols: [],
      open: false,
    };
  }

  // the rows of every rule follow the sources of step 1: one row a source
  function sync() {
    const sources = kit.sources();
    if (!started) {
      started = true;
      rules = [
        {
          id: nextId++,
          title: 'Основное правило',
          enabled: true,
          lists: [...DEFAULT_LISTS],
          mode: 'servers',
          rows: sources.map((source) => newRow(source.id, true)),
          open: true,
          picker: false,
          search: '',
          replaced: [],
        },
      ];
    }
    for (const rule of rules) {
      rule.rows = sources.map(
        (source) =>
          rule.rows.find((row) => row.sourceId === source.id) ??
          newRow(source.id, false),
      );
    }
  }

  function addRule() {
    const sources = kit.sources();
    for (const rule of rules) rule.open = false;
    rules.unshift({
      id: nextId++,
      title: 'Новое правило',
      enabled: true,
      lists: [],
      mode: 'servers',
      // as the package does for a new rule: one row, with the first source
      rows: sources.map((source, index) => newRow(source.id, index === 0)),
      open: true,
      picker: true,
      search: '',
      replaced: [],
    });
    kit.draw();
  }

  function toggleList(rule: Rule, id: string) {
    if (rule.lists.includes(id)) {
      rule.lists = rule.lists.filter((item) => item !== id);
      if (id === 'russia_inside') {
        rule.lists.unshift(...rule.replaced);
        rule.replaced = [];
      }
      return;
    }
    if (REGIONAL_OPTIONS.includes(id)) {
      rule.lists = rule.lists.filter(
        (item) => !REGIONAL_OPTIONS.includes(item),
      );
    }
    rule.lists.push(id);
    if (rule.lists.includes('russia_inside')) {
      const out = rule.lists.filter(
        (item) => !ALLOWED_WITH_RUSSIA_INSIDE.includes(item),
      );
      if (out.length) rule.replaced = out;
      rule.lists = rule.lists.filter((item) =>
        ALLOWED_WITH_RUSSIA_INSIDE.includes(item),
      );
    }
  }

  function barred(rule: Rule, id: string): boolean {
    return (
      rule.lists.includes('russia_inside') &&
      !ALLOWED_WITH_RUSSIA_INSIDE.includes(id)
    );
  }

  function summary(rule: Rule): string {
    const names = rule.lists.map((id) => LABELS[id] ?? id);
    const text = !names.length
      ? 'Списки не выбраны'
      : names.length <= LISTS_SHOWN
        ? names.join(', ')
        : names.slice(0, LISTS_SHOWN).join(', ') +
          ' и ещё ' +
          (names.length - LISTS_SHOWN);
    return rule.enabled ? text : 'Выключено · ' + text;
  }

  // what stops the launch, '' when nothing does
  function problem(): string {
    const sources = kit.sources();
    if (!rules.some((rule) => rule.enabled)) return 'Нет включённых правил.';
    for (const [index, rule] of rules.entries()) {
      if (!rule.enabled) continue;
      if (!rule.lists.length) {
        return 'В правиле ' + (index + 1) + ' не выбраны списки ресурсов.';
      }
      if (rule.mode !== 'servers') continue;
      const servers = rule.rows.reduce((sum, row) => {
        const source = sources.find((item) => item.id === row.sourceId);
        return sum + (source ? gives(source, row) : 0);
      }, 0);
      if (!servers) {
        return 'В правиле ' + (index + 1) + ' не выбран ни один сервер.';
      }
    }
    return '';
  }

  function button(
    className: string,
    children: Child[],
    onClick: (event: MouseEvent) => void,
    attrs: Record<string, string> = {},
  ): HTMLButtonElement {
    const el = h(
      'button',
      { class: className, type: 'button', ...attrs },
      children,
    ) as HTMLButtonElement;
    el.addEventListener('click', (event) => {
      event.stopPropagation();
      onClick(event);
    });
    return el;
  }

  // the settings of a rule are three questions, in one order for every rule
  function step(number: number, text: string): HTMLElement {
    return h('div', { class: 'pdk-route__step' }, [
      h('span', { class: 'pdk-route__step-number' }, [number + '.']),
      text,
    ]);
  }

  function label(text: string): HTMLElement {
    return h('div', { class: 'pdk-wizard__control-label' }, [text]);
  }

  // a field of words: Enter or a comma ends a word, Backspace in the empty field takes the last
  function words(
    title: string,
    list: string[],
    placeholder: string,
    key: string,
  ): HTMLElement {
    const input = h('input', {
      type: 'text',
      'data-focus': key,
      placeholder: list.length ? '' : placeholder,
      autocomplete: 'off',
      spellcheck: 'false',
    }) as HTMLInputElement;
    const commit = (): boolean => {
      const added = input.value
        .split(',')
        .map((word) => word.trim())
        .filter((word) => word && !list.includes(word));
      input.value = '';
      list.push(...added);
      return added.length > 0;
    };
    input.addEventListener('keydown', (event) => {
      if (event.key === 'Enter' || event.key === ',') {
        event.preventDefault();
        commit();
        focusKey = key;
        kit.draw();
      } else if (event.key === 'Backspace' && !input.value && list.length) {
        list.pop();
        focusKey = key;
        kit.draw();
      }
    });
    // a word left in the field counts too; the page is drawn after the click that took the focus
    input.addEventListener('blur', () => {
      if (commit()) setTimeout(kit.draw, 200);
    });
    const box = h('div', { class: 'pdk-route__words' }, [
      ...list.map((word) =>
        h('span', { class: 'pdk-route__word' }, [
          word,
          button(
            'pdk-route__word-x',
            [icon('x', 12)],
            () => {
              list.splice(list.indexOf(word), 1);
              kit.draw();
            },
            { title: 'Убрать', 'aria-label': 'Убрать ' + word },
          ),
        ]),
      ),
      input,
    ]);
    box.addEventListener('click', () => input.focus());
    return h('div', { class: 'pdk-wizard__control' }, [label(title), box]);
  }

  function renderFilter(source: WizardSource, row: Row): HTMLElement {
    const all = serversOf(source);
    const got = new Set(taken(source, row).map((server) => server.name));
    const narrowed = got.size < all.length;
    const schemes = [...new Set(all.map((server) => server.scheme))].filter(
      Boolean,
    );
    const key = 'row-' + row.sourceId + '-';
    return h('div', { class: 'pdk-route__filter' }, [
      h('div', { class: 'pdk-route__filter-fields' }, [
        words('Имя сервера содержит', row.include, 'все', key + 'include'),
        words(
          'Имя сервера не содержит',
          row.exclude,
          'ничего',
          key + 'exclude',
        ),
      ]),
      schemes.length > 1
        ? h('div', { class: 'pdk-wizard__control' }, [
            label('Протоколы'),
            h(
              'div',
              { class: 'pdk-route__tags' },
              schemes.map((scheme) => {
                const on = row.protocols.includes(scheme);
                return button(
                  'pdk-route__pick' + (on ? ' pdk-route__pick--on' : ''),
                  [on ? icon('check', 11) : null, scheme],
                  () => {
                    row.protocols = on
                      ? row.protocols.filter((item) => item !== scheme)
                      : [...row.protocols, scheme];
                    kit.draw();
                  },
                  { 'aria-pressed': String(on) },
                );
              }),
            ),
          ])
        : null,
      h(
        'div',
        { class: 'pdk-route__tags' },
        all.map((server) => {
          const on = narrowed && got.has(server.name);
          const off = !got.has(server.name);
          return button(
            'pdk-route__pick' +
              (on ? ' pdk-route__pick--on' : '') +
              (off ? ' pdk-route__pick--off' : ''),
            [on ? icon('check', 11) : null, server.name],
            () => {
              // the name goes into "contains", or leaves it
              row.include = row.include.includes(server.name)
                ? row.include.filter((word) => word !== server.name)
                : [...row.include, server.name];
              kit.draw();
            },
            { title: server.scheme },
          );
        }),
      ),
    ]);
  }

  function renderRow(source: WizardSource, row: Row): HTMLElement {
    const text = describe(source);
    const all = serversOf(source);
    const canFilter = row.on && filtered(source);
    const count = canFilter ? taken(source, row).length : 0;
    const open = canFilter && row.open;
    const box = h(
      'span',
      { class: 'pdk-route__box' + (row.on ? ' pdk-route__box--on' : '') },
      [row.on ? icon('check', 13) : null],
    );
    const line = h(
      'div',
      {
        class: 'pdk-route__source-row',
        role: 'checkbox',
        'aria-checked': String(row.on),
        tabindex: '0',
      },
      [
        box,
        h(
          'span',
          {
            class:
              'pdk-wizard__source-kind' +
              (row.on ? ' pdk-wizard__source-kind--' + source.kind : ''),
          },
          [icon(kit.kindIcon[source.kind], 16)],
        ),
        h('div', { class: 'pdk-wizard__source-text' }, [
          h('div', { class: 'pdk-wizard__source-title' }, [text.title]),
          h('div', { class: 'pdk-wizard__source-subtitle' }, [text.subtitle]),
        ]),
        canFilter
          ? button(
              'pdk-route__count' +
                (count ? '' : ' pdk-route__count--zero') +
                (open ? ' pdk-route__count--open' : ''),
              [
                count === all.length
                  ? 'Все ' + all.length
                  : count + ' из ' + all.length,
                icon('chevron', 14),
              ],
              () => {
                row.open = !row.open;
                kit.draw();
              },
              { 'aria-expanded': String(open), title: 'Выбрать серверы' },
            )
          : null,
      ],
    );
    const flip = () => {
      row.on = !row.on;
      kit.draw();
    };
    line.addEventListener('click', flip);
    line.addEventListener('keydown', (event) => {
      if (event.key !== ' ' && event.key !== 'Enter') return;
      if (event.target !== line) return;
      event.preventDefault();
      flip();
    });
    return h(
      'div',
      {
        class:
          'pdk-route__source' +
          (row.on ? '' : ' pdk-route__source--off') +
          (open ? ' pdk-route__source--open' : ''),
      },
      [line, open ? renderFilter(source, row) : null],
    );
  }

  function renderPicker(rule: Rule): HTMLElement {
    const search = h('input', {
      class: 'pdk-wizard__text',
      type: 'text',
      placeholder: 'Найти список',
      'data-focus': 'search-' + rule.id,
      autocomplete: 'off',
    }) as HTMLInputElement;
    search.value = rule.search;
    search.addEventListener('input', () => {
      rule.search = search.value;
      focusKey = 'search-' + rule.id;
      kit.draw();
    });
    const query = rule.search.trim().toLowerCase();
    const group = (title: string, note: string, ids: string[]) => {
      const shown = ids.filter((id) =>
        (LABELS[id] ?? id).toLowerCase().includes(query),
      );
      if (!shown.length) return null;
      return h('div', { class: 'pdk-route__group' }, [
        h('div', {}, [
          label(title),
          note ? h('div', { class: 'pdk-wizard__control-help' }, [note]) : null,
        ]),
        h(
          'div',
          { class: 'pdk-route__tags' },
          shown.map((id) => {
            const on = rule.lists.includes(id);
            const el = button(
              'pdk-route__pick' + (on ? ' pdk-route__pick--on' : ''),
              [on ? icon('check', 11) : null, LABELS[id] ?? id],
              () => {
                toggleList(rule, id);
                kit.draw();
              },
              { 'aria-pressed': String(on) },
            );
            if (barred(rule, id)) {
              el.disabled = true;
              el.title = 'Уже входит в Russia inside';
            }
            return el;
          }),
        ),
      ]);
    };
    const close = () => {
      rule.picker = false;
      rule.search = '';
      kit.draw();
    };
    const body = h('div', { class: 'pdk-route__sheet-body' }, [
      group('Списки ресурсов', '', SITE_LISTS),
      group(
        'Регион целиком — только один',
        'Russia inside уже включает первые одиннадцать списков, кроме Telegram.',
        REGIONAL_OPTIONS,
      ),
      group(
        'ASN — сети хостингов целиком',
        'Через серверы пойдёт всё, что размещено у этого хостинга, а не отдельные ресурсы. Выбирайте, только если знаете, зачем.',
        ASN_LISTS,
      ),
    ]);
    if (!body.childElementCount) {
      body.append(
        h('div', { class: 'pdk-wizard__control-help' }, ['Такого списка нет.']),
      );
    }
    // the list keeps its place when a press draws the window again
    body.addEventListener('scroll', () => {
      sheetScroll = body.scrollTop;
    });
    const sheet = h(
      'div',
      {
        class: 'pdk-route__sheet',
        role: 'dialog',
        'aria-modal': 'true',
        'aria-label': 'Списки ресурсов',
      },
      [
        h('div', { class: 'pdk-route__sheet-head' }, [
          h('div', { class: 'pdk-route__sheet-title' }, [
            'Списки ресурсов',
            h('span', { class: 'pdk-wizard__count' }, [
              String(rule.lists.length),
            ]),
          ]),
          button('pdk-wizard__close', [icon('x', 18)], close, {
            title: 'Закрыть',
            'aria-label': 'Закрыть',
          }),
        ]),
        h('div', { class: 'pdk-route__sheet-search' }, [search]),
        body,
        h('div', { class: 'pdk-route__sheet-foot' }, [
          button('pdk-wizard__next', ['Готово'], close),
        ]),
      ],
    );
    sheet.addEventListener('click', (event) => event.stopPropagation());
    const shade = h('div', { class: 'pdk-route__shade' }, [sheet]);
    shade.addEventListener('click', (event) => {
      event.stopPropagation();
      close();
    });
    return shade;
  }

  function renderBody(rule: Rule): HTMLElement {
    const sources = kit.sources();
    const name = h('input', {
      class: 'pdk-wizard__text',
      type: 'text',
      'aria-label': 'Название правила',
    }) as HTMLInputElement;
    name.value = rule.title;
    name.addEventListener('change', () => {
      rule.title = name.value.trim() || rule.title;
      kit.draw();
    });
    return h('div', { class: 'pdk-route__body' }, [
      h('div', { class: 'pdk-wizard__control' }, [label('Название'), name]),
      h('div', { class: 'pdk-route__group' }, [
        step(1, 'Какие ресурсы'),
        h('div', { class: 'pdk-route__tags' }, [
          ...rule.lists.map((id) =>
            h('span', { class: 'pdk-route__tag' }, [
              LABELS[id] ?? id,
              button(
                'pdk-route__tag-x',
                [icon('x', 13)],
                () => {
                  toggleList(rule, id);
                  kit.draw();
                },
                {
                  title: 'Убрать',
                  'aria-label': 'Убрать ' + (LABELS[id] ?? id),
                },
              ),
            ]),
          ),
          button(
            'pdk-route__pick pdk-route__pick--add' +
              (rule.picker ? ' pdk-route__pick--on' : ''),
            ['+ Список'],
            () => {
              rule.picker = !rule.picker;
              rule.search = '';
              sheetScroll = 0;
              // a finger is not given the keyboard before it asks for it
              focusKey =
                rule.picker && window.matchMedia('(pointer: fine)').matches
                  ? 'search-' + rule.id
                  : '';
              kit.draw();
            },
            { 'aria-expanded': String(rule.picker) },
          ),
        ]),
        rule.picker ? renderPicker(rule) : null,
      ]),
      h('div', { class: 'pdk-route__group' }, [
        step(2, 'Что с ними делать'),
        h(
          'div',
          { class: 'pdk-route__modes', role: 'radiogroup' },
          MODES.map(([id, text, note]) =>
            button(
              'pdk-route__mode',
              [
                h('span', { class: 'pdk-route__radio' }),
                h('span', { class: 'pdk-route__mode-text' }, [
                  h('span', { class: 'pdk-route__mode-name' }, [text]),
                  h('span', { class: 'pdk-route__mode-note' }, [note]),
                ]),
              ],
              () => {
                rule.mode = id;
                kit.draw();
              },
              { role: 'radio', 'aria-checked': String(rule.mode === id) },
            ),
          ),
        ),
      ]),
      // the servers are asked for only when the rule proxies
      rule.mode === 'servers'
        ? h('div', { class: 'pdk-route__group' }, [
            step(3, 'Через какие серверы'),
            ...rule.rows.map((row) => {
              const source = sources.find((item) => item.id === row.sourceId);
              return source ? renderRow(source, row) : null;
            }),
            h('div', { class: 'pdk-route__note' }, [
              'Если отмечено несколько, podkop сам выбирает самый быстрый.',
            ]),
          ])
        : null,
    ]);
  }

  function move(id: number, to: number) {
    const from = rules.findIndex((rule) => rule.id === id);
    if (from < 0) return;
    const [rule] = rules.splice(from, 1);
    rules.splice(from < to ? to - 1 : to, 0, rule);
  }

  function renderRule(rule: Rule, index: number): HTMLElement {
    const grip = h(
      'span',
      {
        class: 'pdk-route__grip',
        title: 'Перетащите, чтобы изменить порядок',
        role: 'button',
        tabindex: '0',
        'aria-label': 'Изменить порядок: стрелки вверх и вниз',
        'data-focus': 'grip-' + rule.id,
      },
      [icon('grip', 16)],
    );
    const head = h('div', { class: 'pdk-route__head' }, [
      grip,
      h('span', { class: 'pdk-route__number' }, [String(index + 1)]),
      h('div', { class: 'pdk-route__text' }, [
        h('div', { class: 'pdk-route__title' }, [rule.title]),
        h('div', { class: 'pdk-route__subtitle' }, [summary(rule)]),
      ]),
      button(
        'pdk-route__switch',
        [],
        () => {
          rule.enabled = !rule.enabled;
          kit.draw();
        },
        {
          role: 'switch',
          'aria-checked': String(rule.enabled),
          title: rule.enabled ? 'Выключить правило' : 'Включить правило',
        },
      ),
      button(
        'pdk-wizard__icon-button',
        [icon('trash', 16)],
        () => {
          rules = rules.filter((item) => item.id !== rule.id);
          kit.draw();
        },
        { title: 'Удалить правило', 'aria-label': 'Удалить правило' },
      ),
      button(
        'pdk-wizard__icon-button pdk-route__fold',
        [icon('chevron', 16)],
        () => {
          rule.open = !rule.open;
          kit.draw();
        },
        {
          'aria-expanded': String(rule.open),
          title: rule.open ? 'Свернуть' : 'Раскрыть',
        },
      ),
    ]);
    head.addEventListener('click', () => {
      rule.open = !rule.open;
      kit.draw();
    });
    const card = h(
      'div',
      {
        class:
          'pdk-route__rule' + (rule.enabled ? '' : ' pdk-route__rule--off'),
      },
      [head, rule.open ? renderBody(rule) : null],
    );

    // The order is changed by dragging the card by its handle. By the pointer, not by the drag of
    // the browser, so that a finger does it too; the arrows of the keyboard do it on the handle.
    grip.addEventListener('click', (event) => event.stopPropagation());
    grip.addEventListener('keydown', (event) => {
      const step =
        event.key === 'ArrowUp' ? -1 : event.key === 'ArrowDown' ? 1 : 0;
      const at = rules.findIndex((item) => item.id === rule.id);
      if (!step || at + step < 0 || at + step >= rules.length) return;
      event.preventDefault();
      move(rule.id, step < 0 ? at - 1 : at + 2);
      focusKey = 'grip-' + rule.id;
      kit.draw();
    });
    grip.addEventListener('pointerdown', (event) => {
      const list = card.parentElement;
      if (event.button || !list) return;
      event.preventDefault();
      const cards = Array.from(
        list.querySelectorAll<HTMLElement>('.pdk-route__rule'),
      );
      const from = cards.indexOf(card);
      const startY = event.clientY;
      let to = -1;
      grip.setPointerCapture(event.pointerId);
      card.classList.add('pdk-route__rule--dragging');
      const onMove = (moved: PointerEvent) => {
        card.style.transform = 'translateY(' + (moved.clientY - startY) + 'px)';
        for (const other of cards) {
          other.classList.remove(
            'pdk-route__rule--before',
            'pdk-route__rule--after',
          );
        }
        to = cards.length;
        for (const [index, other] of cards.entries()) {
          if (other === card) continue;
          const rect = other.getBoundingClientRect();
          if (moved.clientY < rect.top + rect.height / 2) {
            to = index;
            break;
          }
        }
        if (to === from || to === from + 1) {
          to = -1;
        } else if (to < cards.length) {
          cards[to].classList.add('pdk-route__rule--before');
        } else {
          cards[cards.length - 1].classList.add('pdk-route__rule--after');
        }
      };
      const onUp = () => {
        grip.removeEventListener('pointermove', onMove);
        if (to >= 0) move(rule.id, to);
        kit.draw();
      };
      grip.addEventListener('pointermove', onMove);
      grip.addEventListener('pointerup', onUp, { once: true });
      grip.addEventListener('pointercancel', onUp, { once: true });
    });
    return card;
  }

  function render(): HTMLElement {
    sync();
    const stop = problem();
    return h('div', { class: 'pdk-wizard__body' }, [
      // the way back stands where the manual form of step 1 has it
      button('pdk-wizard__back', [icon('back', 14), 'К источникам'], kit.back),
      h('div', { class: 'pdk-wizard__intro' }, [
        h('div', { class: 'pdk-wizard__heading' }, ['Маршрутизация']),
        h('div', { class: 'pdk-wizard__lead' }, [
          'Правила применяются сверху вниз: срабатывает первое, в котором нашёлся ресурс. Всё, чего нет в правилах, идёт напрямую.',
        ]),
      ]),
      h('div', { class: 'pdk-route' }, [
        h('div', { class: 'pdk-wizard__list-head' }, [
          h('div', { class: 'pdk-wizard__list-title' }, [
            'Правила',
            h('span', { class: 'pdk-wizard__count' }, [String(rules.length)]),
          ]),
          button(
            'pdk-wizard__ghost-button',
            [icon('plus', 14), 'Добавить правило'],
            addRule,
          ),
        ]),
        ...rules.map(renderRule),
        !rules.length
          ? h('div', { class: 'pdk-wizard__empty' }, [
              icon('inbox', 24),
              h('div', {}, ['Правил нет: всё идёт напрямую.']),
            ])
          : null,
      ]),
      stop || notice
        ? h(
            'div',
            {
              class: 'pdk-wizard__alert pdk-wizard__alert--warn',
              role: 'status',
            },
            [
              icon('warn', 18),
              h('div', { class: 'pdk-wizard__alert-text' }, [stop || notice]),
            ],
          )
        : null,
    ]);
  }

  return {
    render,
    ready: () => !problem(),
    // what the rules are, for the config that is written
    rules(): RuleValue[] {
      sync();
      return rules.map((rule) => ({
        title: rule.title,
        enabled: rule.enabled,
        lists: [...rule.lists],
        mode: rule.mode,
        rows: rule.rows
          .filter((row) => row.on)
          .map((row) => ({
            sourceId: row.sourceId,
            include: [...row.include],
            exclude: [...row.exclude],
            protocols: [...row.protocols],
          })),
      }));
    },
    say(text: string) {
      notice = text;
    },
    // the field that was typed in keeps the focus over a redraw
    // Escape closes the window of lists, if one is open
    escape(): boolean {
      const rule = rules.find((item) => item.picker);
      if (!rule) return false;
      rule.picker = false;
      rule.search = '';
      kit.draw();
      return true;
    },
    afterDraw(root: HTMLElement) {
      const body = root.querySelector<HTMLElement>('.pdk-route__sheet-body');
      if (body) body.scrollTop = sheetScroll;
      if (!focusKey) return;
      const el = root.querySelector<HTMLElement>(
        '[data-focus="' + focusKey + '"]',
      );
      focusKey = '';
      if (!el) return;
      el.focus();
      if (el instanceof HTMLInputElement) {
        el.setSelectionRange(el.value.length, el.value.length);
      }
    },
  };
}
