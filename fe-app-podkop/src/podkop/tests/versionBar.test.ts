import { beforeEach, describe, expect, it, vi } from 'vitest';
import { FakeNode } from './viewHarness';

// what the backend answers show_version, and the warnings of the page
let answer: () => Promise<string>;
const warn = vi.fn();
vi.mock('../methods', () => ({
  PodkopShellMethods: { showVersion: () => answer() },
}));
vi.mock('../services', () => ({ logger: { warn } }));

const { createVersionBar, reloadWithoutCache, versionText } = await import(
  '../versionBar'
);

const older = (page: string, backend: string) =>
  `This page (version ${page}) is older than the backend (version ${backend}): reload it without the cache`;
const newer = (page: string, backend: string) =>
  `This page (version ${page}) is newer than the backend (version ${backend}): after an update restart podkop, after a downgrade reload this page without the cache`;

describe('versionText', () => {
  it.each([
    ['0.8.23', '0.8.24'],
    ['0.8.9', '0.8.10'],
    ['0.8.23', '0.9.0'],
    // a candidate is newer than the release it is named by, and older than the next one
    ['0.8.23', '0.8.23.1'],
    ['0.8.23.1', '0.8.23.2'],
    ['0.8.23.1', '0.8.24'],
    // an opkg package writes the v of the tag
    ['v0.8.23', 'v0.8.24'],
    ['0.8.23', 'v0.8.24'],
    // the page of the podkop of before
    ['v0.7.17', '0.8.23'],
    // a build by date
    ['0.8.23', '0.24112026'],
  ])('page %s, backend %s: the page is older', (page, backend) => {
    expect(versionText(page, backend)).toBe(older(page, backend));
  });

  it.each([
    ['0.8.23', '0.8.22'],
    ['0.8.23.1', '0.8.23'],
    ['0.8.24', '0.8.23.9'],
    ['v0.8.23', '0.7.17'],
  ])('page %s, backend %s: the page is newer', (page, backend) => {
    expect(versionText(page, backend)).toBe(newer(page, backend));
  });

  it.each([
    ['0.8.23', '0.8.23'],
    ['v0.8.23', '0.8.23'],
    ['0.8.23-r1', '0.8.23'],
    ['0.8.23.1', '0.8.23.1'],
    ['0.24112026', '0.24112026'],
  ])('page %s, backend %s: the same', (page, backend) => {
    expect(versionText(page, backend)).toBe('');
  });

  it.each([
    // nothing answered, or it is not a version
    ['0.8.23', ''],
    ['0.8.23', 'unknown'],
    ['0.8.23', 'Usage: /usr/bin/podkop <command>'],
    // a backend built without a version
    ['0.8.23', '0.8.0-dev'],
    // the page of the sources: no package wrote its version
    ['__COMPILED_VERSION_VARIABLE__', '0.8.23'],
    ['__COMPILED_VERSION_VARIABLE__', '0.8.0-dev'],
  ])('page %s, backend %j: not known', (page, backend) => {
    expect(versionText(page, backend)).toBe('');
  });
});

describe('createVersionBar', () => {
  // an element of E(), with the style of a browser's
  class Bar extends FakeNode {
    style: { display?: string };

    constructor(
      tag: string,
      attrs?: Record<string, unknown>,
      children?: unknown,
    ) {
      super(tag, attrs, children);
      this.style = /display: none/.test(String(attrs?.style ?? ''))
        ? { display: 'none' }
        : {};
    }
  }

  let kept: Map<string, string>;

  beforeEach(() => {
    kept = new Map();
    warn.mockClear();
    vi.stubGlobal('E', (...args: ConstructorParameters<typeof Bar>) => {
      return new Bar(...args);
    });
    vi.stubGlobal('sessionStorage', {
      getItem: (key: string) => kept.get(key) ?? null,
      setItem: (key: string, value: string) => kept.set(key, value),
    });
  });

  async function shown(page: string, backend: string | Error) {
    answer = () =>
      backend instanceof Error
        ? Promise.reject(backend)
        : Promise.resolve(backend);
    const bar = createVersionBar(page) as unknown as Bar;
    // hidden until the backend has answered
    expect(bar.style.display).toBe('none');
    await new Promise((resolve) => setTimeout(resolve));
    return bar;
  }

  // a click of the button of this name
  const click = (bar: Bar, name: string) =>
    (
      bar.querySelectorAll('button').find((item) => item.textContent === name)
        ?.attrs.click as () => void
    )();
  const dismiss = (bar: Bar) => click(bar, 'Dismiss');

  it('is the warning of LuCI with the text, the reload and Dismiss', async () => {
    const bar = await shown('0.8.23', '0.8.24');
    expect(bar.style.display).toBe('');
    expect(bar.attrs.class).toBe('alert-message warning');
    expect(bar.querySelector('.podkop-apply-text')?.textContent).toBe(
      older('0.8.23', '0.8.24'),
    );
    expect(
      bar.querySelectorAll('button').map((item) => item.textContent),
    ).toEqual(['Reload without the cache', 'Dismiss']);
  });

  it('reloads the page without the cache', async () => {
    const reload = vi.fn();
    vi.stubGlobal('performance', { getEntriesByType: () => [] });
    vi.stubGlobal('location', { reload });
    click(await shown('0.8.23', '0.8.24'), 'Reload without the cache');
    await new Promise((resolve) => setTimeout(resolve));
    expect(reload).toHaveBeenCalledTimes(1);
  });

  it('is hidden and empty with the same versions, or one not known', async () => {
    for (const [page, backend] of [
      ['0.8.23', '0.8.23'],
      ['0.8.23', ''],
      ['__COMPILED_VERSION_VARIABLE__', '0.8.23'],
    ]) {
      const bar = await shown(page, backend);
      expect(bar.style.display).toBe('none');
      expect(bar.children).toEqual([]);
    }
  });

  it('is hidden when the question fails', async () => {
    const bar = await shown('0.8.23', new Error('no answer'));
    expect(bar.style.display).toBe('none');
    expect(warn).toHaveBeenCalledTimes(1);
  });

  it('is hidden by Dismiss, in the pages this tab loads later too', async () => {
    const bar = await shown('0.8.23', '0.8.24');
    dismiss(bar);
    expect(bar.style.display).toBe('none');
    expect((await shown('0.8.23', '0.8.24')).style.display).toBe('none');
  });

  it('is there again for other versions', async () => {
    dismiss(await shown('0.8.23', '0.8.24'));
    expect((await shown('0.8.23', '0.8.25')).style.display).toBe('');
    expect((await shown('0.8.22', '0.8.24')).style.display).toBe('');
  });

  it('works without a storage', async () => {
    const refuse = () => {
      throw new Error('denied');
    };
    vi.stubGlobal('sessionStorage', { getItem: refuse, setItem: refuse });
    const bar = await shown('0.8.23', '0.8.24');
    expect(bar.style.display).toBe('');
    dismiss(bar);
    expect(bar.style.display).toBe('none');
    expect(warn).not.toHaveBeenCalled();
  });
});

describe('reloadWithoutCache', () => {
  const VIEW = 'http://192.168.1.1/luci-static/resources/view/podkop/';
  const order: string[] = [];

  beforeEach(() => {
    order.length = 0;
    warn.mockClear();
    vi.stubGlobal('performance', {
      getEntriesByType: (type: string) =>
        type === 'resource'
          ? [
              { name: 'http://192.168.1.1/luci-static/resources/ui.js?v=1' },
              { name: VIEW + 'podkop.js?v=1' },
              { name: 'http://192.168.1.1/ubus/' },
              { name: VIEW + 'main.js?v=1' },
            ]
          : [],
    });
    vi.stubGlobal('location', { reload: () => order.push('reload') });
  });

  it('asks the files of the page past the cache, whole, and reloads then', async () => {
    const fetched = vi.fn((file: string) =>
      Promise.resolve({
        arrayBuffer: async () => {
          await new Promise((resolve) => setTimeout(resolve, 5));
          order.push(file);
        },
      }),
    );
    vi.stubGlobal('fetch', fetched);
    await reloadWithoutCache();
    expect(fetched.mock.calls).toEqual([
      [VIEW + 'podkop.js?v=1', { cache: 'reload' }],
      [VIEW + 'main.js?v=1', { cache: 'reload' }],
    ]);
    expect(order).toEqual([
      VIEW + 'podkop.js?v=1',
      VIEW + 'main.js?v=1',
      'reload',
    ]);
  });

  it('reloads when the router does not answer for a file', async () => {
    vi.stubGlobal('fetch', () => Promise.reject(new Error('no answer')));
    await reloadWithoutCache();
    expect(order).toEqual(['reload']);
    expect(warn).toHaveBeenCalledTimes(2);
  });
});
