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
