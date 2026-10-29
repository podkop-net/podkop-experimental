import { beforeEach, describe, expect, it, vi } from 'vitest';

// the router, standing in: check_links answers by what a link holds
const asked: string[][] = [];
let answer: (links: string[]) => unknown = (links) => ({
  success: true,
  data: links.map((link) =>
    link.includes('type=kcp')
      ? { ok: false, error: 'the mKCP transport is not supported' }
      : { ok: true },
  ),
});
vi.mock('../methods', () => ({
  PodkopShellMethods: {
    checkLinks: async (links: string[]) => {
      asked.push(links);
      return answer(links);
    },
  },
}));
vi.mock('../services', () => ({ logger: { warn: () => {} } }));

const { linkPlaces, linkLabel, checkLinksBeforeSave, linkBatches } =
  await import('../linkCheck');

const GOOD = 'vless://b831381d-6324-4d53-ad4f-8cda48b30811@192.0.2.1:443#DE-1';
const KCP =
  'vless://b831381d-6324-4d53-ad4f-8cda48b30811@[2001:db8::1]:443?type=kcp#NL%20kcp';

// the sources of the settings, as uci.sections gives them
function links(name: string, list: string | string[], label?: string) {
  return { '.name': name, type: 'links', link: list, label };
}

describe('linkPlaces', () => {
  it('lists the links of the sources of links, with their places and labels', () => {
    const places = linkPlaces([
      links('src1', [`  ${GOOD}`]),
      links('src2', [GOOD, '', KCP], 'Mine'),
      { '.name': 'src3', type: 'subscription', url: 'https://example.org/s' },
      { '.name': 'src4', type: 'json', outbound_json: '{"type":"direct"}' },
      { '.name': 'src5', link: [KCP] },
    ]);
    expect(places).toEqual([
      {
        section: 'src1',
        label: 'DE-1',
        option: 'link',
        index: 1,
        count: 1,
        link: GOOD,
      },
      {
        section: 'src2',
        label: 'Mine',
        option: 'link',
        index: 1,
        count: 2,
        link: GOOD,
      },
      {
        section: 'src2',
        label: 'Mine',
        option: 'link',
        index: 2,
        count: 2,
        link: KCP,
      },
    ]);
  });

  it('takes a link written as an option, not a list', () => {
    expect(
      linkPlaces([links('src1', GOOD)]).map((place) => place.link),
    ).toEqual([GOOD]);
  });
});

describe('linkLabel', () => {
  it('names a link by its name, kind and server, never its secrets', () => {
    expect(linkLabel(GOOD)).toBe('«DE-1» (vless, 192.0.2.1:443)');
    expect(linkLabel(KCP)).toBe('«NL kcp» (vless, [2001:db8::1]:443)');
    expect(linkLabel('trojan://secret@t.example.org:443')).toBe(
      'trojan, t.example.org:443',
    );
    expect(linkLabel('trojan://secret@t.example.org:443')).not.toContain(
      'secret',
    );
  });
});

describe('checkLinksBeforeSave', () => {
  beforeEach(() => {
    asked.length = 0;
  });

  it('asks once for the links of the sources and returns the refused ones', async () => {
    const problems = await checkLinksBeforeSave([
      links('src1', [KCP]),
      links('src2', [GOOD, KCP]),
    ]);
    expect(asked).toEqual([[KCP, GOOD]]);
    expect(
      problems.map((problem) => [
        problem.section,
        problem.index,
        problem.error,
      ]),
    ).toEqual([
      ['src1', 1, 'the mKCP transport is not supported'],
      ['src2', 2, 'the mKCP transport is not supported'],
    ]);
  });

  it('asks nothing when a link has a wrong form: the window of the source refuses it', async () => {
    const problems = await checkLinksBeforeSave([
      links('src1', [KCP, 'vless://no-port@192.0.2.1']),
    ]);
    expect(problems).toEqual([]);
    expect(asked).toEqual([]);
  });

  it('asks nothing when no source has links', async () => {
    expect(
      await checkLinksBeforeSave([
        { '.name': 'src1', type: 'subscription', url: 'https://e.org/s' },
      ]),
    ).toEqual([]);
    expect(asked).toEqual([]);
  });

  it('asks for many long links in parts below the limit of uhttpd', async () => {
    const long = Array.from(
      { length: 150 },
      (_x, index) => `${GOOD}&extra=${'x'.repeat(500)}${index}`,
    );
    const problems = await checkLinksBeforeSave([
      links('src1', [...long, KCP]),
    ]);
    expect(asked.length).toBeGreaterThan(1);
    expect(asked.flat()).toEqual([...long, KCP]);
    for (const part of asked)
      expect(JSON.stringify(part).length).toBeLessThan(65536 - 1024);
    expect(problems.map((problem) => problem.index)).toEqual([151]);
  });

  it('keeps a link longer than a part alone', () => {
    expect(
      linkBatches(['a', 'x'.repeat(50000), 'b']).map((part) => part.length),
    ).toEqual([1, 1, 1]);
  });

  it('refuses nothing when the router does not answer', async () => {
    answer = () => ({ success: false, error: '' });
    expect(await checkLinksBeforeSave([links('src1', [KCP])])).toEqual([]);
    answer = () => {
      throw new Error('timeout');
    };
    expect(await checkLinksBeforeSave([links('src1', [KCP])])).toEqual([]);
  });
});
