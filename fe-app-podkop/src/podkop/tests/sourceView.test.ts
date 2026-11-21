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
