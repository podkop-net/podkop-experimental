import {
  BOOTSTRAP_DNS_SERVER_OPTIONS,
  DNS_SERVER_OPTIONS,
} from '../../constants';
import { validateDNS } from '../../validators/validateDns';
import type { DnsValue } from './config';

// Step 3 of the wizard: the DNS settings of the package (config settings and its config
// dns_server rows), held in the memory of the page. The Bootstrap DNS server stands first: the
// servers under it are found through it.

type Child = Node | string | null | undefined | false;

export interface DnsKit {
  h(
    tag: string,
    attrs?: Record<string, string>,
    children?: Child[],
  ): HTMLElement;
  icon(name: string, size?: number): HTMLElement;
  draw(): void;
  back(): void;
  // the DNS servers of the provider the router knows now
  providerDns?: () => Promise<string[]>;
}

interface Server {
  id: number;
  type: string;
  server: string;
}

const TYPES: [string, string][] = [
  ['doh', 'DNS over HTTPS (DoH)'],
  ['dot', 'DNS over TLS (DoT)'],
  ['udp', 'UDP (незащищённый DNS)'],
  ['provider', 'DNS провайдера'],
];

const ADDRESSES: [string, string][] = [
  ['prefer_ipv4', 'Сначала IPv4, IPv6 — если IPv4 нет'],
  ['ipv4_only', 'Только IPv4'],
  ['both', 'IPv4 и IPv6: выбирает устройство'],
];

const MODES: [string, string][] = [
  ['order', 'По порядку'],
  ['fastest', 'Сначала самый быстрый'],
];

export function createDns(kit: DnsKit) {
  const { h, icon } = kit;
  // what a fresh install has
  let bootstrap = '77.88.8.8';
  let servers: Server[] = [{ id: 1, type: 'udp', server: '77.88.8.8' }];
  let nextId = 2;
  let mode = 'order';
  let addresses = 'prefer_ipv4';
  let ttl = '60';
  let more = false;
  let notice = '';
  let provider: string[] | null = null;
  let asked = false;

  function button(
    className: string,
    children: Child[],
    onClick: () => void,
    attrs: Record<string, string> = {},
  ): HTMLButtonElement {
    const el = h(
      'button',
      { class: className, type: 'button', ...attrs },
      children,
    ) as HTMLButtonElement;
    el.addEventListener('click', onClick);
    return el;
  }

  function select(
    value: string,
    options: [string, string][],
    onChange: (value: string) => void,
    name: string,
  ): HTMLElement {
    const el = h('select', {
      class: 'pdk-wizard__text',
      'aria-label': name,
    }) as HTMLSelectElement;
    for (const [key, text] of options) {
      const option = h('option', { value: key }, [text]) as HTMLOptionElement;
      option.selected = key === value;
      el.append(option);
    }
    el.addEventListener('change', () => onChange(el.value));
    return h('span', { class: 'pdk-wizard__select' }, [
      el,
      icon('chevron', 16),
    ]);
  }

  // an address is chosen from the known ones or typed: a field with a list under it
  function address(
    value: string,
    known: Record<string, string>,
    onChange: (value: string) => void,
    name: string,
    listId: string,
  ): HTMLElement {
    const input = h('input', {
      class: 'pdk-wizard__text',
      type: 'text',
      list: listId,
      'aria-label': name,
      placeholder: 'Адрес сервера',
      autocomplete: 'off',
      spellcheck: 'false',
    }) as HTMLInputElement;
    input.value = value;
    // the value is kept as it is typed; the window is not drawn again under the cursor
    input.addEventListener('input', () => onChange(input.value.trim()));
    return h('span', { class: 'pdk-dns__address' }, [
      input,
      h(
        'datalist',
        { id: listId },
        Object.entries(known).map(([key, text]) =>
          h('option', { value: key }, [text]),
        ),
      ),
    ]);
  }

  function step(number: number, text: string, extra?: Child): HTMLElement {
    return h('div', { class: 'pdk-route__step' }, [
      h('span', { class: 'pdk-route__step-number' }, [number + '.']),
      text,
      extra,
    ]);
  }

  function note(text: string): HTMLElement {
    return h('div', { class: 'pdk-route__note' }, [text]);
  }

  function askProvider() {
    if (asked || !kit.providerDns) return;
    asked = true;
    kit
      .providerDns()
      .then((list) => {
        provider = list;
        kit.draw();
      })
      .catch(() => {
        provider = [];
        kit.draw();
      });
  }

  function move(id: number, to: number) {
    const from = servers.findIndex((item) => item.id === id);
    if (from < 0) return;
    const [item] = servers.splice(from, 1);
    servers.splice(from < to ? to - 1 : to, 0, item);
  }

  function renderServer(server: Server, index: number): HTMLElement {
    const grip = h(
      'span',
      {
        class: 'pdk-route__grip',
        title: 'Перетащите, чтобы изменить порядок',
        role: 'button',
        tabindex: '0',
        'aria-label': 'Изменить порядок: стрелки вверх и вниз',
      },
      [icon('grip', 16)],
    );
    let value: HTMLElement;
    if (server.type === 'provider') {
      askProvider();
      value = h('span', { class: 'pdk-dns__provider' }, [
        provider === null
          ? 'Адреса берутся у провайдера.'
          : provider.length
            ? 'Сейчас у провайдера: ' + provider.join(', ')
            : 'Роутер сейчас не знает DNS-серверов провайдера.',
      ]);
    } else {
      value = address(
        server.server,
        DNS_SERVER_OPTIONS,
        (next) => {
          server.server = next;
        },
        'Адрес DNS-сервера ' + (index + 1),
        'pdk-dns-list-' + server.id,
      );
    }
    const del = button(
      'pdk-wizard__icon-button',
      [icon('trash', 16)],
      () => {
        servers = servers.filter((item) => item.id !== server.id);
        notice = '';
        kit.draw();
      },
      { title: 'Удалить сервер', 'aria-label': 'Удалить сервер' },
    );
    // one DNS server is needed at least
    del.disabled = servers.length < 2;
    const card = h('div', { class: 'pdk-dns__server' }, [
      grip,
      h('span', { class: 'pdk-route__number' }, [String(index + 1)]),
      h('span', { class: 'pdk-dns__type' }, [
        select(
          server.type,
          TYPES,
          (next) => {
            server.type = next;
            notice = '';
            kit.draw();
          },
          'Тип DNS-сервера ' + (index + 1),
        ),
      ]),
      value,
      del,
    ]);

    // the order is changed as the order of the rules is: by the handle, or by the arrows on it
    grip.addEventListener('keydown', (event) => {
      const by =
        event.key === 'ArrowUp' ? -1 : event.key === 'ArrowDown' ? 1 : 0;
      const at = servers.findIndex((item) => item.id === server.id);
      if (!by || at + by < 0 || at + by >= servers.length) return;
      event.preventDefault();
      move(server.id, by < 0 ? at - 1 : at + 2);
      kit.draw();
    });
    grip.addEventListener('pointerdown', (event) => {
      const list = card.parentElement;
      if (event.button || !list) return;
      event.preventDefault();
      const cards = Array.from(
        list.querySelectorAll<HTMLElement>('.pdk-dns__server'),
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
        for (const [at, other] of cards.entries()) {
          if (other === card) continue;
          const rect = other.getBoundingClientRect();
          if (moved.clientY < rect.top + rect.height / 2) {
            to = at;
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
        if (to >= 0) move(server.id, to);
        kit.draw();
      };
      grip.addEventListener('pointermove', onMove);
      grip.addEventListener('pointerup', onUp, { once: true });
      grip.addEventListener('pointercancel', onUp, { once: true });
    });
    return card;
  }

  // what stops the save, '' when nothing does
  function problem(): string {
    if (!validateDNS(bootstrap.trim()).valid) {
      return 'Адрес Bootstrap DNS указан неверно.';
    }
    for (const [index, server] of servers.entries()) {
      if (server.type === 'provider') continue;
      if (!validateDNS(server.server.trim()).valid) {
        return 'Адрес DNS-сервера ' + (index + 1) + ' указан неверно.';
      }
    }
    if (!/^\d+$/.test(ttl.trim()) || Number(ttl) < 1) {
      return 'Время хранения ответов — целое число секунд, не меньше 1.';
    }
    return '';
  }

  function render(): HTMLElement {
    const ttlInput = h('input', {
      class: 'pdk-wizard__text',
      type: 'text',
      inputmode: 'numeric',
      'aria-label': 'Хранить ответы, секунд',
    }) as HTMLInputElement;
    ttlInput.value = ttl;
    ttlInput.addEventListener('input', () => {
      ttl = ttlInput.value;
    });
    return h('div', { class: 'pdk-wizard__body' }, [
      button(
        'pdk-wizard__back',
        [icon('back', 14), 'К маршрутизации'],
        kit.back,
      ),
      h('div', { class: 'pdk-wizard__intro' }, [
        h('div', { class: 'pdk-wizard__heading' }, ['DNS']),
        h('div', { class: 'pdk-wizard__lead' }, [
          'Уже заполнено — можно не менять.',
        ]),
      ]),
      h('div', { class: 'pdk-route__group' }, [
        step(1, 'Bootstrap DNS'),
        note(
          'Его роутер спрашивает первым: по нему он находит адреса DNS-серверов ниже, когда они заданы именем, например dns.adguard-dns.com. Без него такие серверы не заработают.',
        ),
        h('div', { class: 'pdk-dns__bootstrap' }, [
          address(
            bootstrap,
            BOOTSTRAP_DNS_SERVER_OPTIONS,
            (next) => {
              bootstrap = next;
            },
            'Bootstrap DNS-сервер',
            'pdk-dns-list-bootstrap',
          ),
        ]),
      ]),
      h('div', { class: 'pdk-route__group' }, [
        h('div', { class: 'pdk-wizard__list-head' }, [
          step(
            2,
            'DNS-серверы',
            h('span', { class: 'pdk-wizard__count pdk-dns__count' }, [
              String(servers.length),
            ]),
          ),
          button('pdk-wizard__ghost-button', ['+ Добавить сервер'], () => {
            servers.push({
              id: nextId++,
              type: 'doh',
              server: Object.keys(DNS_SERVER_OPTIONS)[0] ?? '1.1.1.1',
            });
            notice = '';
            kit.draw();
          }),
        ]),
        note(
          'Через них идут DNS-запросы устройств сети и самого роутера — для ресурсов, которых нет в правилах. Ресурсам из правил адрес выдаёт сам podkop.',
        ),
        ...servers.map(renderServer),
        servers.length > 1
          ? h('div', { class: 'pdk-dns__mode' }, [
              h('span', { class: 'pdk-dns__mode-label' }, ['Как опрашивать']),
              h(
                'span',
                { class: 'pdk-dns__switch', role: 'radiogroup' },
                MODES.map(([id, text]) =>
                  button(
                    '',
                    [text],
                    () => {
                      mode = id;
                      kit.draw();
                    },
                    { role: 'radio', 'aria-checked': String(mode === id) },
                  ),
                ),
              ),
            ])
          : null,
        servers.length > 1
          ? note(
              mode === 'order'
                ? 'По порядку: следующий сервер спрашивают, только если верхний не ответил.'
                : 'Сначала спрашивают сервер, который отвечал быстрее всех; следующий — если он не ответил.',
            )
          : null,
      ]),
      h('div', { class: 'pdk-route__group' }, [
        button(
          'pdk-wizard__back',
          [icon('chevron', 14), 'Ещё настройки'],
          () => {
            more = !more;
            kit.draw();
          },
          {
            'aria-expanded': String(more),
            class: 'pdk-wizard__back pdk-dns__more',
          },
        ),
        more
          ? h('div', { class: 'pdk-dns__fields' }, [
              h('label', { class: 'pdk-wizard__control' }, [
                h('span', { class: 'pdk-wizard__control-label' }, [
                  'Адреса в ответах DNS',
                ]),
                select(
                  addresses,
                  ADDRESSES,
                  (next) => {
                    addresses = next;
                  },
                  'Адреса в ответах DNS',
                ),
              ]),
              h('label', { class: 'pdk-wizard__control' }, [
                h('span', { class: 'pdk-wizard__control-label' }, [
                  'Хранить ответы, секунд',
                ]),
                ttlInput,
              ]),
            ])
          : null,
      ]),
      notice
        ? h(
            'div',
            {
              class: 'pdk-wizard__alert pdk-wizard__alert--warn',
              role: 'status',
            },
            [
              icon('warn', 18),
              h('div', { class: 'pdk-wizard__alert-text' }, [notice]),
            ],
          )
        : null,
    ]);
  }

  return {
    render,
    problem,
    say(text: string) {
      notice = text;
    },
    value(): DnsValue {
      return {
        bootstrap,
        servers: servers.map((item) => ({
          type: item.type,
          server: item.server,
        })),
        mode,
        addresses,
        ttl,
      };
    },
  };
}
