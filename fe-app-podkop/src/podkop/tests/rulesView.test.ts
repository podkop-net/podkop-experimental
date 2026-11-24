import { describe, expect, it, vi } from 'vitest';
import { FakeNode, loadView } from './viewHarness';

type Fn = (...args: unknown[]) => unknown;

// The window of a rule (view/podkop/rules.js): "Only for devices" against Fully Routed IPs. A
// hand edit can store a fully routed IP outside the devices; the window is then not saved
// (isValid of only_devices), and LuCI saves a window silently.

const CONFLICT = {
  '.type': 'section',
  only_devices: ['192.168.1.10'],
  fully_routed_ips: ['192.168.1.20'],
};

const NOTE =
  'Fully Routed IPs 192.168.1.20 are not among the devices of “Only for devices”';

// the field of only_devices as LuCI draws it, on the tab Main of the window: the menu of the
// tabs before their group, a pane a tab
function drawnWindow() {
  const field = new FakeNode('div', { class: 'cbi-value-field' });
  const frame = new FakeNode(
    'div',
    { class: 'cbi-value', id: 'cbi-podkop-rule1-only_devices' },
    [field],
  );
  const link = new FakeNode('a', { href: '#' });
  link.click = vi.fn();
  const menu = new FakeNode('ul', { class: 'cbi-tabmenu' }, [
    new FakeNode('li', { 'data-tab': 'main', class: 'cbi-tab-disabled' }, [
      link,
    ]),
    new FakeNode('li', { 'data-tab': 'servers', class: 'cbi-tab' }, [
      new FakeNode('a', { href: '#' }),
    ]),
  ]);
  const group = new FakeNode('div', { class: 'cbi-section-node-tabbed' }, [
    new FakeNode('div', { 'data-tab': 'main' }, [frame]),
    new FakeNode('div', { 'data-tab': 'servers' }),
  ]);
  new FakeNode('div', {}, [menu, group]);
  return { field, frame, link };
}

async function ruleWindow(settings: Record<string, unknown> = CONFLICT) {
  const view = loadView('rules.js', { rule1: settings });
  view.exports.createRulesContent(view.section, [], null, []);
  await view.section.loadOptions('rule1');
  const devices = view.section.lookup('only_devices');
  const fully = view.section.lookup('fully_routed_ips');
  // the window holds what it opened with
  devices.window.rule1 = devices.cfgvalue('rule1');
  fully.window.rule1 = fully.cfgvalue('rule1');
  const drawn = drawnWindow();
  view.map.elements['cbi-podkop-rule1-only_devices'] = drawn.frame;
  return { ...view, devices, drawn };
}

const notes = (field: FakeNode) => field.querySelectorAll('.pdk-devices-note');

// Save of the window: the section's own handleModalSave, else LuCI's
function saveWindow(view: Awaited<ReturnType<typeof ruleWindow>>) {
  const { form, section, map } = view;
  const handle = (section.handleModalSave ??
    form.GridSection.prototype.handleModalSave) as Fn;
  return handle.call(
    section,
    { section: 'rule1', lookupOption: map.lookupOption.bind(map) },
    null,
  );
}

describe('the devices of a rule in its window', () => {
  it('tells the stored conflict when the window opens', async () => {
    const { form, devices, drawn } = await ruleWindow();
    form.DynamicList.prototype.render = () => Promise.resolve(drawn.frame);
    expect(await devices.call('render', 0, 'rule1', false)).toBe(drawn.frame);
    expect(notes(drawn.field)).toHaveLength(1);
    expect(drawn.field.textContent).toContain(NOTE);
  });

  it('draws no note when the lists agree', async () => {
    const { form, devices, drawn } = await ruleWindow({
      ...CONFLICT,
      only_devices: ['192.168.1.0/24'],
    });
    form.DynamicList.prototype.render = () => Promise.resolve(drawn.frame);
    await devices.call('render', 0, 'rule1', false);
    expect(notes(drawn.field)).toHaveLength(0);
  });

  // the user is on another tab and presses Save: the window stays open
  it('shows why a Save is refused, on the tab of the field', async () => {
    const view = await ruleWindow();
    const { form, devices, drawn } = view;
    const save = vi.fn(() => Promise.resolve());
    form.GridSection.prototype.handleModalSave = save;
    expect(devices.call('isValid', 'rule1')).toBe(false);
    await saveWindow(view);
    expect(save).toHaveBeenCalledOnce();
    expect(notes(drawn.field)).toHaveLength(1);
    expect(drawn.field.textContent).toContain(NOTE);
    expect(drawn.link.click).toHaveBeenCalledOnce();
  });

  it('saves as LuCI does when the lists agree', async () => {
    const view = await ruleWindow({
      ...CONFLICT,
      fully_routed_ips: ['192.168.1.10'],
    });
    const { form, drawn } = view;
    const save = vi.fn(() => Promise.resolve());
    form.GridSection.prototype.handleModalSave = save;
    await saveWindow(view);
    expect(save).toHaveBeenCalledOnce();
    expect(notes(drawn.field)).toHaveLength(0);
    expect(drawn.link.click).not.toHaveBeenCalled();
  });
});

describe('the choices of Only for devices', () => {
  it("are the devices the router knows, not the router's own addresses", () => {
    const view = loadView('rules.js', { rule1: { '.type': 'section' } });
    const hints = {
      hosts: {
        'D4:5F:AA:00:00:01': { name: 'OpenWrt', ipaddrs: ['192.168.1.1'] },
        'D4:5F:AA:00:00:02': { name: 'OpenWrt', ipaddrs: ['192.168.0.2'] },
        'AA:BB:CC:00:00:02': { name: 'tv', ipaddrs: ['192.168.1.50'] },
      },
    };
    view.exports.createRulesContent(view.section, [], hints, [
      'D4:5F:AA:00:00:01',
      'D4:5F:AA:00:00:02',
    ]);
    expect(view.section.lookup('only_devices').keylist).toEqual([
      '192.168.1.50',
    ]);
  });
});

// The rows of a rule: the field Protocols of the tabs Servers and Fallback, the line of a row in the
// list, and Matched
const VLESS = 'vless://u@203.0.113.7:443#NL%201';
const HY2 = 'hy2://p@203.0.113.8:443#NL%202';
const TROJAN = 'trojan://p@203.0.113.9:443#DE%201';

type Row = Record<string, unknown>;

function rowsOfRule(row: Row, source: Row, main: Row = {}) {
  const view = loadView(
    'rules.js',
    {
      rule1: { '.type': 'section' },
      src1: { '.type': 'source', label: 'Lab', ...source },
      row1: {
        '.type': 'member',
        section: 'rule1',
        role: 'server',
        source: 'src1',
        ...row,
      },
    },
    main,
  );
  view.exports.createRulesContent(
    view.section,
    ['urltest.fallbacks'],
    null,
    [],
  );
  const table = (option: string) => {
    const found = view.section.lookup(option).subsection;
    if (!found) throw new Error(`${option} has no table`);
    return found;
  };
  return {
    ...view,
    servers: table('_servers'),
    fallbacks: table('_fallbacks'),
  };
}

const links = (...list: string[]) => ({ type: 'links', link: list });

// the text of Matched, and its title, for the row as it is
function matched(view: ReturnType<typeof rowsOfRule>): FakeNode {
  return view.servers.lookup('_matched').call('cfgvalue', 'row1') as FakeNode;
}

// the line of the rule in the list
function line(view: ReturnType<typeof rowsOfRule>): string {
  return (view.section.lookup('_rows').call('textvalue', 'rule1') as FakeNode)
    .textContent;
}

describe('the protocols of a row', () => {
  it('is a field of the servers and of the fallbacks, all by default', () => {
    const view = rowsOfRule({}, links(VLESS, HY2));
    for (const table of [view.servers, view.fallbacks]) {
      const field = table.lookup('protocols');
      expect(field).toBeInstanceOf(view.form.MultiValue);
      expect(field.placeholder).toBe('all');
      expect(field.load('row1')).toEqual([]);
    }
  });

  it('offers the protocols by the names of the dashboard', () => {
    const view = rowsOfRule({ protocols: 'hy2, vles' }, links(VLESS, HY2));
    const field = view.servers.lookup('protocols');
    const widget = { style: { minWidth: '' } };
    const shown = vi.fn(() => widget);
    (view.form.MultiValue.prototype as Row).renderWidget = shown;
    const stored = field.load('row1');
    expect(stored).toEqual(['hysteria2', 'vles']);
    expect(field.call('renderWidget', 'row1', 0, stored)).toBe(widget);
    expect(shown).toHaveBeenCalledWith('row1', 0, stored);
    // the source of the row keeps its place
    expect(widget.style.minWidth).toBe('110px');
    expect((field.keylist as string[]).slice(0, 5)).toEqual([
      'vless',
      'vmess',
      'trojan',
      'shadowsocks',
      'hysteria2',
    ]);
    expect((field.vallist as string[]).slice(0, 5)).toEqual([
      'VLESS',
      'VMess',
      'Trojan',
      'Shadowsocks',
      'Hysteria2',
    ]);
    expect((field.keylist as string[]).at(-1)).toBe('vles');
    expect((field.vallist as string[]).at(-1)).toBe('vles (unknown protocol)');
  });

  it('knows the type of an outbound JSON', () => {
    const view = rowsOfRule(
      { protocols: ['ssh'] },
      { type: 'json', outbound_json: '{"type":"ssh"}' },
    );
    const field = view.servers.lookup('protocols');
    (view.form.MultiValue.prototype as Row).renderWidget = () => ({
      style: {},
    });
    field.call('renderWidget', 'row1', 0, field.load('row1'));
    expect((field.vallist as string[]).at(-1)).toBe('ssh');
  });

  it('is asked of a source with servers, not of an interface', () => {
    const asked = (source: Row) =>
      rowsOfRule({}, source)
        .servers.lookup('protocols')
        .call('checkDepends', 'row1');
    expect(asked(links(VLESS))).toBe(true);
    expect(asked({ type: 'subscription', url: 'https://a.example/s' })).toBe(
      true,
    );
    expect(asked({ type: 'json', outbound_json: '{"type":"ssh"}' })).toBe(true);
    expect(asked({ type: 'interface', interface: 'awg0' })).toBe(false);
    expect(asked({})).toBe(false);
  });

  it('counts the servers of links the words and the protocols take', () => {
    const count = (row: Row, ...list: string[]) =>
      matched(rowsOfRule(row, links(...list))).textContent;
    expect(count({}, VLESS, HY2, TROJAN)).toBe('3 of 3');
    expect(count({ protocols: ['vless'] }, VLESS, HY2, TROJAN)).toBe('1 of 3');
    expect(
      count(
        { include: ['NL'], protocols: ['hy2', 'trojan'] },
        VLESS,
        HY2,
        TROJAN,
      ),
    ).toBe('1 of 3');
    expect(count({ include: ['JP'] }, VLESS, HY2)).toBe(
      '0 of 2, check the words',
    );
    expect(count({ protocols: ['tuic'] }, VLESS, HY2)).toBe(
      '0 of 2, check the words and the protocols',
    );
    // one server: the words do not choose, the protocols do
    expect(count({ include: ['JP'] }, VLESS)).toBe('1');
    expect(count({ protocols: ['vless'] }, VLESS)).toBe('1');
    expect(count({ protocols: ['tuic'] }, VLESS)).toBe(
      '0 of 1, check the words and the protocols',
    );
  });

  it('counts the server of an outbound JSON by its type, an interface always', () => {
    const json = { type: 'json', outbound_json: '{"type":"socks"}' };
    const count = (row: Row, source: Row) =>
      matched(rowsOfRule(row, source)).textContent;
    expect(count({ protocols: 'SOCKS5' }, json)).toBe('1');
    expect(count({ protocols: 'vless' }, json)).toBe(
      '0 of 1, check the words and the protocols',
    );
    expect(count({ protocols: 'vless' }, { type: 'interface' })).toBe('1');
  });

  it('asks the router for a subscription with the protocols', async () => {
    vi.useFakeTimers();
    const groupCheck = vi.fn(() =>
      Promise.resolve({
        success: true,
        data: { chosen: ['NL 1'], total: 4 },
      }),
    );
    const view = rowsOfRule(
      { include: ['NL'], protocols: ['Hysteria2', 'vless'] },
      { type: 'subscription', url: 'https://a.example/s' },
      { PodkopShellMethods: { groupCheck }, listRequest: () => ({}) },
    );
    const node = matched(view);
    await vi.runAllTimersAsync();
    vi.useRealTimers();
    expect(groupCheck).toHaveBeenCalledOnce();
    expect(groupCheck.mock.calls[0]).toMatchObject([
      {
        subscriptions: ['src1'],
        include: ['NL'],
        exclude: [],
        protocols: ['vless', 'hysteria2'],
      },
    ]);
    expect(node.textContent).toBe('1 of 4');
    expect(node.title).toBe('NL 1');
  });

  it('is told in the line of the rule', () => {
    expect(
      line(
        rowsOfRule(
          { include: ['NL'], exclude: ['2'], protocols: ['hy2', 'VLESS'] },
          links(VLESS, HY2),
        ),
      ),
    ).toContain('Lab: NL, without 2, only VLESS, Hysteria2');
    expect(line(rowsOfRule({ protocols: ['vless'] }, links(VLESS)))).toContain(
      'Lab: only VLESS',
    );
    expect(
      line(rowsOfRule({ protocols: ['vless'] }, { type: 'interface' })),
    ).not.toContain('only');
  });
});

// How a rule chooses among its fallbacks: the field of the tab Fallback, the fields of the loss it
// brings, and the line of the rule in the list
describe('the choice among the fallbacks', () => {
  function rule(features: string[], options: Row = {}) {
    const view = loadView('rules.js', {
      rule1: { '.type': 'section', ...options },
      src1: { '.type': 'source', label: 'Lab', ...links(VLESS, HY2) },
      row1: {
        '.type': 'member',
        section: 'rule1',
        role: 'server',
        source: 'src1',
      },
      row2: {
        '.type': 'member',
        section: 'rule1',
        role: 'fallback',
        source: 'src1',
      },
      row3: {
        '.type': 'member',
        section: 'rule1',
        role: 'fallback',
        source: 'block',
      },
    });
    view.exports.createRulesContent(view.section, features, null, []);
    return view;
  }
  const MODES = ['urltest.fallbacks', 'urltest.modes'];

  it('is in order by default, or one of the modes of the engine', () => {
    const view = rule(MODES);
    const field = view.section.lookup('fallback_choice');
    expect(field).toBeInstanceOf(view.form.ListValue);
    expect(field.tab).toBe('fallback');
    expect(field.keylist).toEqual(['order', 'fastest', 'loss', 'balance']);
    expect(field.default).toBe('order');
    // "order" is not written: the settings of a rule nobody touched stay as they are
    expect(field.rmempty).toBe(true);
  });

  it('offers what the engine has', () => {
    expect(
      rule(['urltest.fallbacks']).section.lookup('fallback_choice').keylist,
    ).toEqual(['order', 'fastest']);
  });

  it('brings the fields of the loss, as the server choice does', () => {
    const { section } = rule(MODES);
    expect(section.lookup('loss_check_interval').deps).toEqual([
      { server_choice: 'loss' },
      { server_choice: 'balance' },
      { fallback_choice: 'loss' },
      { fallback_choice: 'balance' },
    ]);
    expect(section.lookup('loss_threshold').deps).toEqual([
      { server_choice: 'balance' },
      { fallback_choice: 'balance' },
    ]);
  });

  it('is told in the list of the rules', () => {
    const told = (choice?: string) =>
      (
        rule(MODES, choice ? { fallback_choice: choice } : {})
          .section.lookup('_rows')
          .call('textvalue', 'rule1') as FakeNode
      ).textContent;
    const rows = 'Lab; Block';
    expect(told()).toContain(`Fallback: ${rows}`);
    expect(told('order')).toContain(`Fallback: ${rows}`);
    expect(told('random')).toContain(`Fallback: ${rows}`);
    expect(told('fastest')).toContain(`Fallback, the fastest: ${rows}`);
    expect(told('loss')).toContain(`Fallback, avoiding loss: ${rows}`);
    expect(told('balance')).toContain(`Fallback, balance: ${rows}`);
  });
});
