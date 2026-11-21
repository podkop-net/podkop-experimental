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
