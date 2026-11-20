import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { getLatestRelease, readCachedRelease } from '../getLatestRelease';

const KEY = 'podkop-latest-release';
const PLACEHOLDER = '__COMPILED_VERSION_VARIABLE__';

describe('readCachedRelease', () => {
  const minute = 60 * 1000;
  const page = 'v0.8.21';

  it('gives a tag asked less than an hour ago', () => {
    const raw = JSON.stringify({ tag: 'v0.8.1', at: 1000, page });
    expect(readCachedRelease(1000 + 60 * minute - 1, raw, page)).toBe('v0.8.1');
  });

  it('asks again after an hour', () => {
    const raw = JSON.stringify({ tag: 'v0.8.1', at: 1000, page });
    expect(readCachedRelease(1000 + 60 * minute, raw, page)).toBeUndefined();
  });

  it('keeps a failure for 10 minutes', () => {
    const raw = JSON.stringify({ tag: '', at: 1000, page });
    expect(readCachedRelease(1000 + 10 * minute - 1, raw, page)).toBe('');
    expect(readCachedRelease(1000 + 10 * minute, raw, page)).toBeUndefined();
  });

  it('asks again for a page of another version', () => {
    const tag = JSON.stringify({ tag: 'v0.8.20', at: 1000, page: 'v0.8.20' });
    expect(readCachedRelease(1000, tag, page)).toBeUndefined();
    const failure = JSON.stringify({ tag: '', at: 1000, page: 'v0.8.20' });
    expect(readCachedRelease(1000, failure, page)).toBeUndefined();
    // the same version as apk writes it is another page all the same
    const apk = JSON.stringify({ tag: 'v0.8.21', at: 1000, page: '0.8.21' });
    expect(readCachedRelease(1000, apk, page)).toBeUndefined();
  });

  it('asks again for what an older page kept, without its version', () => {
    const raw = JSON.stringify({ tag: 'v0.8.20', at: 1000 });
    expect(readCachedRelease(1000, raw, page)).toBeUndefined();
  });

  it('asks again when nothing or something broken is kept', () => {
    expect(readCachedRelease(0, null, page)).toBeUndefined();
    expect(readCachedRelease(0, '{', page)).toBeUndefined();
    expect(
      readCachedRelease(0, `{"at":0,"page":"${page}"}`, page),
    ).toBeUndefined();
    expect(
      readCachedRelease(0, `{"tag":"v1","page":"${page}"}`, page),
    ).toBeUndefined();
  });
});

describe('getLatestRelease', () => {
  let stored: Map<string, string>;
  let storage: {
    getItem: ReturnType<typeof vi.fn>;
    setItem: ReturnType<typeof vi.fn>;
  };
  let fetchMock: ReturnType<typeof vi.fn>;
  let answer: () => Promise<unknown>;

  beforeEach(() => {
    stored = new Map();
    storage = {
      getItem: vi.fn((key: string) => stored.get(key) ?? null),
      setItem: vi.fn((key: string, value: string) => {
        stored.set(key, value);
      }),
    };
    answer = async () => ({
      ok: true,
      json: async () => ({ tag_name: 'v0.8.21' }),
    });
    fetchMock = vi.fn(() => answer());
    vi.stubGlobal('localStorage', storage);
    vi.stubGlobal('fetch', fetchMock);
  });

  afterEach(() => vi.unstubAllGlobals());

  function kept() {
    return JSON.parse(stored.get(KEY) ?? 'null');
  }

  it('asks GitHub again after an upgrade of the page, then keeps the answer', async () => {
    stored.set(
      KEY,
      JSON.stringify({ tag: 'v0.8.20', at: Date.now(), page: 'v0.8.20' }),
    );

    expect(await getLatestRelease('v0.8.21')).toBe('v0.8.21');
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0][0]).toBe(
      'https://api.github.com/repos/podkop-net/podkop-experimental/releases/latest',
    );
    expect(fetchMock.mock.calls[0][1]).toMatchObject({ cache: 'no-cache' });
    expect(kept()).toMatchObject({ tag: 'v0.8.21', page: 'v0.8.21' });

    expect(await getLatestRelease('v0.8.21')).toBe('v0.8.21');
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('asks GitHub again over what an older page kept', async () => {
    stored.set(KEY, JSON.stringify({ tag: 'v0.8.19', at: Date.now() }));

    expect(await getLatestRelease('v0.8.21')).toBe('v0.8.21');
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(kept()).toMatchObject({ tag: 'v0.8.21', page: 'v0.8.21' });
  });

  it('keeps a failure for the page that asked', async () => {
    answer = async () => {
      throw new Error('no network');
    };

    expect(await getLatestRelease('v0.8.21')).toBe('');
    expect(kept()).toMatchObject({ tag: '', page: 'v0.8.21' });
    expect(await getLatestRelease('v0.8.21')).toBe('');
    expect(fetchMock).toHaveBeenCalledTimes(1);

    // a page of another version does not take the failure
    answer = async () => ({
      ok: true,
      json: async () => ({ tag_name: 'v0.8.21' }),
    });
    expect(await getLatestRelease('v0.8.22')).toBe('v0.8.21');
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('keeps nothing for a page of the sources', async () => {
    stored.set(
      KEY,
      JSON.stringify({ tag: 'v0.8.19', at: Date.now(), page: PLACEHOLDER }),
    );

    expect(await getLatestRelease(PLACEHOLDER)).toBe('v0.8.21');
    expect(await getLatestRelease(PLACEHOLDER)).toBe('v0.8.21');
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(storage.getItem).not.toHaveBeenCalled();
    expect(storage.setItem).not.toHaveBeenCalled();
  });

  it('asks every time without storage', async () => {
    vi.stubGlobal('localStorage', {
      getItem: () => {
        throw new Error('denied');
      },
      setItem: () => {
        throw new Error('denied');
      },
    });

    expect(await getLatestRelease('v0.8.21')).toBe('v0.8.21');
    expect(await getLatestRelease('v0.8.21')).toBe('v0.8.21');
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
});
