import { describe, expect, it, vi } from 'vitest';
import { FakeNode, loadView, toArray } from './viewHarness';

// The window of a subscription (view/podkop/source.js) against LuCI's form and uci.

const SUBSCRIPTION = {
  '.type': 'source',
  type: 'subscription',
  url: 'https://sub.example.com/api/sub/abc',
};

// the view with the subscription src1, its window open with the values given, and the router
// running it with state (asked as the list is drawn)
async function sourceWindow(
  options: Record<string, unknown>,
  window: Record<string, unknown> = {},
  state: Record<string, unknown> = { name: 'src1', attempted: 't0' },
) {
  const updateStart = vi.fn(() => Promise.resolve({ success: true, data: [] }));
  const view = loadView(
    'source.js',
    { src1: { ...SUBSCRIPTION, ...options } },
    {
      PodkopShellMethods: {
        subscriptionStatus: () =>
          Promise.resolve({ success: true, data: [state] }),
        subscriptionUpdateStart: updateStart,
      },
    },
  );
  view.exports.createSourceContent(view.section, []);
  await view.section.load('src1');
  await view.section.loadOptions('src1');
  Object.entries(window).forEach(([option, value]) => {
    view.section.lookup(option).window.src1 = value;
  });
  const status = new FakeNode('div');
  view.elements['pdk-status-src1'] = status;
  return { ...view, updateStart, status };
}

describe('the extra headers of a subscription', () => {
  // uci set podkop.src1.header='Authorization: Bearer abc': the backend sends it as one line
  it('loads an option of one line as that line, not as its words', async () => {
    const { section } = await sourceWindow({
      header: 'Authorization: Bearer abc',
    });
    const loaded = section.lookup('header').cfgvalue('src1');
    // the list of LuCI shows L.toArray of it, and Save compares the list with it (isEqual)
    expect(toArray(loaded)).toEqual(['Authorization: Bearer abc']);
    expect(loaded).toEqual(['Authorization: Bearer abc']);
  });

  it('loads a list as it is, and none as none', async () => {
    const lines = ['Authorization: Bearer abc', 'X-Api-Key: k'];
    const { section } = await sourceWindow({ header: lines });
    expect(section.lookup('header').cfgvalue('src1')).toEqual(lines);
    const empty = await sourceWindow({});
    expect(empty.section.lookup('header').cfgvalue('src1')).toBeUndefined();
  });
});

describe('Update now of a subscription', () => {
  const update = (view: Awaited<ReturnType<typeof sourceWindow>>) =>
    view.section.lookup('_update').call('onclick', null, 'src1');

  it('downloads when the window holds what the router runs with', async () => {
    const view = await sourceWindow(
      { user_agent: 'INCY' },
      { user_agent: 'INCY' },
    );
    await update(view);
    expect(view.updateStart).toHaveBeenCalledWith('src1');
  });

  // the window's Save stages the User-Agent: uci.get gives the staged value, the router runs the
  // one before it
  it('asks for Save & Apply when the User-Agent is saved and not applied', async () => {
    const view = await sourceWindow(
      { user_agent: 'INCY' },
      { user_agent: 'INCY' },
    );
    view.uci.records = [['set', 'src1', 'user_agent', 'INCY']];
    await update(view);
    expect(view.updateStart).not.toHaveBeenCalled();
    expect(view.status.textContent).toContain(
      'Save & Apply first: the router asks with the User-Agent and headers it runs with',
    );
  });

  it('asks for Save & Apply when a header is saved and not applied', async () => {
    const view = await sourceWindow(
      { header: ['Authorization: Bearer new'] },
      { header: ['Authorization: Bearer new'] },
    );
    view.uci.records = [
      ['remove', 'src1', 'header'],
      ['list-add', 'src1', 'header', 'Authorization: Bearer new'],
    ];
    await update(view);
    expect(view.updateStart).not.toHaveBeenCalled();
  });

  it('asks for Save & Apply when the address is saved and not applied', async () => {
    const view = await sourceWindow({}, { url: SUBSCRIPTION.url });
    view.uci.records = [['set', 'src1', 'url', SUBSCRIPTION.url]];
    await update(view);
    expect(view.updateStart).not.toHaveBeenCalled();
    expect(view.status.textContent).toContain(
      'Save & Apply first: the router downloads the address it runs with',
    );
  });

  it('is not held by the changes of another source', async () => {
    const view = await sourceWindow(
      { user_agent: 'INCY' },
      { user_agent: 'INCY' },
    );
    view.uci.records = [['set', 'src2', 'user_agent', 'Other']];
    await update(view);
    expect(view.updateStart).toHaveBeenCalledWith('src1');
  });
});

// LuCI's parse of the window at Save, for the options of what a subscription is asked with: a
// shown option writes a value that changed and removes an empty one, a hidden one (its depends
// not met) is removed. The User-Agent shows for custom only.
function saveRequest(view: Awaited<ReturnType<typeof sourceWindow>>) {
  const { section } = view;
  const preset = section.lookup('user_agent_preset');
  const shown = (option: string) =>
    option !== 'user_agent' || preset.formvalue('src1') === 'custom';
  ['user_agent_preset', 'user_agent'].forEach((name) => {
    const option = section.lookup(name);
    const value = option.formvalue('src1');
    if (!shown(name) || value == null || value === '') {
      option.call('remove', 'src1');
    } else if (value !== option.cfgvalue('src1')) {
      option.call('write', 'src1', value);
    }
  });
  return view.uci.values.src1;
}

describe('Ask as of a subscription', () => {
  it.each([
    [{}, 'podkop'],
    [{ user_agent_preset: 'happ' }, 'happ'],
    [{ user_agent_preset: 'custom', user_agent: 'Hiddify' }, 'custom'],
    // a User-Agent without a preset: a file written by hand
    [{ user_agent: 'INCY' }, 'custom'],
    [{ user_agent_preset: 'sing-box', user_agent: 'stale' }, 'sing-box'],
    [{ user_agent_preset: 'other' }, 'other'],
  ])('opens %j as %s', async (options, shown) => {
    const { section } = await sourceWindow(options);
    expect(section.lookup('user_agent_preset').cfgvalue('src1')).toBe(shown);
  });

  it('lists the presets, and keeps one set by hand', async () => {
    const view = await sourceWindow({ user_agent_preset: 'other' });
    view.form.ListValue.prototype.renderWidget = () => null;
    const preset = view.section.lookup('user_agent_preset');
    preset.call('renderWidget', 'src1', 0, 'other');
    expect(preset.keylist).toEqual([
      'podkop',
      'happ',
      'incy',
      'sing-box',
      'custom',
      'other',
    ]);
    expect(preset.vallist).toEqual([
      'podkop',
      'Happ',
      'INCY',
      'sing-box (SFA)',
      'Another User-Agent',
      'other',
    ]);
  });

  it('unsets both for podkop', async () => {
    const view = await sourceWindow(
      { user_agent_preset: 'custom', user_agent: 'INCY' },
      { user_agent_preset: 'podkop', user_agent: 'INCY' },
    );
    const saved = saveRequest(view);
    expect(saved.user_agent_preset).toBeUndefined();
    expect(saved.user_agent).toBeUndefined();
  });

  it('sets a preset and unsets the User-Agent', async () => {
    const view = await sourceWindow(
      { user_agent: 'INCY' },
      { user_agent_preset: 'happ', user_agent: 'INCY' },
    );
    const saved = saveRequest(view);
    expect(saved.user_agent_preset).toBe('happ');
    expect(saved.user_agent).toBeUndefined();
  });

  it('sets both for another User-Agent', async () => {
    const view = await sourceWindow(
      {},
      { user_agent_preset: 'custom', user_agent: ' Hiddify ' },
    );
    const saved = saveRequest(view);
    expect(saved.user_agent_preset).toBe('custom');
    expect(saved.user_agent).toBe('Hiddify');
  });

  it('leaves a User-Agent written by hand as it is when nothing changed', async () => {
    const view = await sourceWindow(
      { user_agent: 'INCY' },
      { user_agent_preset: 'custom', user_agent: 'INCY' },
    );
    const saved = saveRequest(view);
    expect(saved.user_agent_preset).toBeUndefined();
    expect(saved.user_agent).toBe('INCY');
  });

  it('asks for the User-Agent of another one', async () => {
    const view = await sourceWindow(
      {},
      { user_agent_preset: 'custom', user_agent: '' },
    );
    const agent = view.section.lookup('user_agent');
    expect(agent.call('validate', 'src1', ' ')).toBe(
      'Type the User-Agent, or choose podkop in Ask as',
    );
    expect(agent.call('validate', 'src1', 'Hiddify')).toBe(true);
    expect(agent.call('validate', 'src1', 'ИНСИ')).toBe(
      'Only Latin letters, digits, spaces and the signs of the keyboard',
    );
    // hidden under a preset: an empty field is no fault
    view.section.lookup('user_agent_preset').window.src1 = 'happ';
    expect(agent.call('validate', 'src1', '')).toBe(true);
  });

  it('is unset with the type of another source', async () => {
    const view = await sourceWindow(
      { user_agent_preset: 'happ' },
      { type: 'links' },
    );
    view.section.lookup('user_agent_preset').call('remove', 'src1');
    expect(view.uci.values.src1.user_agent_preset).toBeUndefined();
  });

  it('is replaced by a pasted text', async () => {
    const view = await sourceWindow({
      user_agent_preset: 'custom',
      user_agent: 'INCY',
    });
    view.section
      .lookup('_paste')
      .call('write', 'src1', 'https://other.example.com/sub/x');
    expect(view.uci.values.src1.user_agent_preset).toBeUndefined();
    expect(view.uci.values.src1.user_agent).toBeUndefined();
  });
});

// the window with Load: the router's download of the list answered at once with preview
async function loadWindow(
  window: Record<string, unknown>,
  preview: Record<string, unknown> = { route: 'direct', servers: [] },
) {
  const loadStart = vi.fn(() =>
    Promise.resolve({
      success: true,
      data: { id: 'job1', state: 'done', preview },
    }),
  );
  const view = loadView(
    'source.js',
    { src1: { ...SUBSCRIPTION } },
    {
      PodkopShellMethods: {
        subscriptionStatus: () => Promise.resolve({ success: true, data: [] }),
        subscriptionLoadStart: loadStart,
      },
    },
  );
  view.exports.createSourceContent(view.section, []);
  await view.section.load('src1');
  await view.section.loadOptions('src1');
  Object.entries(window).forEach(([option, value]) => {
    view.section.lookup(option).window.src1 = value;
  });
  const result = new FakeNode('div');
  view.elements['pdk-preview-src1'] = result;
  await view.section.lookup('_load').call('onclick', null, 'src1');
  return { ...view, loadStart, result };
}

describe('Load of a subscription', () => {
  it.each([
    [{ user_agent_preset: 'podkop', user_agent: 'INCY' }, undefined],
    [
      { user_agent_preset: 'happ', user_agent: 'INCY' },
      { user_agent_preset: 'happ' },
    ],
    [
      { user_agent_preset: 'custom', user_agent: ' INCY ' },
      { user_agent_preset: 'custom', user_agent: 'INCY' },
    ],
  ])('asks as the window says: %j', async (window, request) => {
    const { loadStart } = await loadWindow(window);
    expect(loadStart).toHaveBeenCalledWith(SUBSCRIPTION.url, request ?? {});
  });

  it('asks for the User-Agent of another one before it loads', async () => {
    const { loadStart, result } = await loadWindow({
      user_agent_preset: 'custom',
      user_agent: '',
    });
    expect(loadStart).not.toHaveBeenCalled();
    expect(result.textContent).toBe(
      'Type the User-Agent, or choose podkop in Ask as',
    );
  });

  it('tells the preset, the format and the links podkop made', async () => {
    const { result } = await loadWindow(
      { user_agent_preset: 'happ' },
      {
        route: 'direct',
        preset: 'happ',
        agent: 'Happ/4.8.3/Linux',
        format: 'xray',
        configs: 11,
        servers: [
          { name: 'NL', scheme: 'vless', link: 'vless://a@nl', made: true },
          { name: 'DE', scheme: 'vless', link: 'vless://b@de' },
        ],
      },
    );
    const text = result.textContent;
    expect(text).toContain('Asked as: Happ');
    expect(text).toContain('User-Agent: Happ/4.8.3/Linux');
    expect(text).toContain(
      "Servers taken from the provider's Xray configurations (11); their rules, DNS and balancers are not used",
    );
    const title =
      "The link was made by podkop from the provider's configuration: other apps may read it differently";
    const buttons = result.querySelectorAll('button');
    const copy = buttons.filter((button) => button.textContent === 'Copy');
    expect(copy.map((button) => button.getAttribute('title'))).toEqual([
      title,
      null,
    ]);
    const all = buttons.find(
      (button) => button.textContent === 'Copy all links',
    );
    expect(all?.getAttribute('title')).toBe(title);
  });

  it('tells a list of sing-box and none of links', async () => {
    const singbox = await loadWindow(
      { user_agent_preset: 'sing-box' },
      {
        route: 'direct',
        preset: 'sing-box',
        agent: 'SFA (sing-box 1.14.4; language en_US)',
        format: 'sing-box',
        servers: [{ name: 'NL', scheme: 'vless', link: 'vless://a@nl' }],
      },
    );
    expect(singbox.result.textContent).toContain('Asked as: sing-box (SFA)');
    expect(singbox.result.textContent).toContain(
      "Servers taken from the provider's sing-box configuration; its rules, DNS and groups are not used",
    );
    const links = await loadWindow(
      { user_agent_preset: 'podkop' },
      {
        route: 'direct',
        servers: [{ name: 'NL', scheme: 'vless', link: 'vless://a@nl' }],
      },
    );
    expect(links.result.textContent).not.toContain('Servers taken');
    expect(links.result.textContent).not.toContain('Asked as');
    expect(
      links.result
        .querySelectorAll('button')
        .every((button) => button.getAttribute('title') === null),
    ).toBe(true);
  });

  it.each([
    [
      'json',
      'The provider sent JSON that is not a configuration of Xray or sing-box',
    ],
    [
      'happ-crypt',
      'The provider sent only links encrypted for Happ (happ://crypt…), which only Happ reads. In Ask as, choose another app, such as INCY, or ask the provider for plain links',
    ],
    [
      'happ-crypt-agent',
      'The provider sent this User-Agent only links encrypted for Happ (happ://crypt…), which only Happ reads. In Ask as, choose another app, such as INCY, or podkop',
    ],
    [
      'json-agent',
      'The provider sent JSON that is not a configuration of Xray or sing-box to this User-Agent. In Ask as, choose another app or podkop',
    ],
    // a preset this podkop does not know, refused by the router for Load
    [
      'request',
      'Ask as has a value this podkop does not know: choose another one in the list',
      ['preset', '0', ''],
    ],
    // control: a line of the request the router refuses
    [
      'request',
      'The User-Agent or a header cannot be sent: Header 2: The value is empty',
      ['empty', '2', 'X-A'],
    ],
  ])('tells the failure %s', async (code, text, args?: string[]) => {
    const { result } = await loadWindow(
      { user_agent_preset: 'incy' },
      {
        error: 'english text of the router',
        error_code: code,
        error_args: args,
        preset: 'incy',
        agent: 'INCY/3.9.1/linux',
        servers: [],
      },
    );
    expect(result.textContent).toContain(text);
    expect(result.textContent).toContain('Asked as: INCY');
  });
});

describe('the state of a subscription', () => {
  it('tells what the list in use came as, and the preset it is asked as', async () => {
    const view = await sourceWindow(
      { user_agent_preset: 'incy' },
      {},
      {
        name: 'src1',
        servers: 3,
        usable: 3,
        changed: '2026-11-21T10:00:00Z',
        checked: '2026-11-21T10:00:00Z',
        route: 'direct',
        preset: 'incy',
        agent: 'INCY/3.9.1/linux',
        format: 'xray',
        configs: 2,
      },
    );
    const box = view.section.lookup('_status').call('cfgvalue', 'src1');
    const text = (box as FakeNode).textContent;
    expect(text).toContain(
      "Servers taken from the provider's Xray configurations (2); their rules, DNS and balancers are not used",
    );
    expect(text).toContain('Asked as: INCY');
    expect(text).toContain('User-Agent: INCY/3.9.1/linux');
  });

  it('tells a preset of the settings this podkop does not know', async () => {
    const view = await sourceWindow(
      { user_agent_preset: 'other' },
      {},
      {
        name: 'src1',
        servers: 1,
        usable: 1,
        changed: '2026-11-21T10:00:00Z',
        request_problems: [{ line: 0, code: 'preset', text: 'english' }],
      },
    );
    const box = view.section.lookup('_status').call('cfgvalue', 'src1');
    expect((box as FakeNode).textContent).toContain(
      "Left out of the request: Ask as has a value this podkop does not know: podkop's own User-Agent is sent",
    );
  });

  it('tells another User-Agent as it is', async () => {
    const view = await sourceWindow(
      { user_agent: 'Hiddify' },
      {},
      {
        name: 'src1',
        servers: 1,
        usable: 1,
        changed: '2026-11-21T10:00:00Z',
        preset: 'custom',
        agent: 'Hiddify',
      },
    );
    const box = view.section.lookup('_status').call('cfgvalue', 'src1');
    const text = (box as FakeNode).textContent;
    expect(text).toContain('User-Agent: Hiddify');
    expect(text).not.toContain('Asked as');
    expect(text).not.toContain('Servers taken');
  });
});

describe('what the provider told of the traffic', () => {
  const GIB = 1024 ** 3;
  const USED = { traffic: true, upload: GIB / 2, download: 3 * GIB };
  const END = '2027-01-15T12:00:00Z';

  // the column State of the list, its lines, and the text of the window's state
  async function shown(provider?: Record<string, unknown>) {
    const view = await sourceWindow(
      {},
      {},
      {
        name: 'src1',
        servers: 3,
        usable: 3,
        changed: '2026-11-21T10:00:00Z',
        provider,
      },
    );
    const cell = view.section.lookup('_state').call('textvalue', 'src1');
    const box = view.section.lookup('_status').call('cfgvalue', 'src1');
    return {
      list: (cell as FakeNode).elements.map((line) => line.textContent),
      window: (box as FakeNode).textContent,
    };
  }

  it('with a limit: what is used of it', async () => {
    const { list, window } = await shown({ ...USED, total: 10 * GIB });
    expect(list).toEqual(['Servers: 3', '3.5 GiB of 10 GiB']);
    expect(window).toContain('Traffic: 3.5 GiB of 10 GiB');
  });

  it('without a limit: what is used, and that there is none', async () => {
    const { list, window } = await shown(USED);
    expect(list).toEqual(['Servers: 3', '3.5 GiB, no limit']);
    expect(window).toContain('Traffic: 3.5 GiB, no limit');
  });

  it('nothing used yet', async () => {
    const { list, window } = await shown({ traffic: true });
    expect(list).toEqual(['Servers: 3', '0 B, no limit']);
    expect(window).toContain('Traffic: 0 B, no limit');
  });

  it('with the end of the subscription after it', async () => {
    const { list } = await shown({ ...USED, expire: END });
    expect(list).toEqual([
      'Servers: 3',
      '3.5 GiB, no limit, until Jan 15, 2027',
    ]);
  });

  it('no numbers of the traffic: nothing of it', async () => {
    const { list, window } = await shown({ expire: END, title: 'Example' });
    expect(list).toEqual(['Servers: 3', 'until Jan 15, 2027']);
    expect(window).not.toContain('Traffic');
    expect((await shown(undefined)).list).toEqual(['Servers: 3']);
  });
});

describe('Update now with a preset', () => {
  const update = (view: Awaited<ReturnType<typeof sourceWindow>>) =>
    view.section.lookup('_update').call('onclick', null, 'src1');

  it('asks for Save & Apply when the preset is saved and not applied', async () => {
    const view = await sourceWindow(
      { user_agent_preset: 'happ' },
      { user_agent_preset: 'happ' },
    );
    view.uci.records = [['set', 'src1', 'user_agent_preset', 'happ']];
    await update(view);
    expect(view.updateStart).not.toHaveBeenCalled();
    expect(view.status.textContent).toContain(
      'Save & Apply first: the router asks with the User-Agent and headers it runs with',
    );
  });

  it('asks for Save & Apply when the window chose another preset', async () => {
    const view = await sourceWindow(
      { user_agent: 'INCY' },
      { user_agent_preset: 'incy', user_agent: 'INCY' },
    );
    await update(view);
    expect(view.updateStart).not.toHaveBeenCalled();
  });

  it('downloads when the window shows a User-Agent written by hand as custom', async () => {
    const view = await sourceWindow(
      { user_agent: 'INCY' },
      { user_agent_preset: 'custom', user_agent: 'INCY' },
    );
    await update(view);
    expect(view.updateStart).toHaveBeenCalledWith('src1');
  });
});
