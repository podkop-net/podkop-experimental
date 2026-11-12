import { beforeAll, describe, expect, it, vi } from 'vitest';
import { renderDefaultState } from '../partials/renderSections';
import type { ISectionChecks } from '../partials/renderSections';
import type { IDetectWidget } from '../../../services';
import type { Podkop } from '../../../types';

interface Node {
  tag: string;
  attr: Record<string, unknown>;
  children: (Node | string)[];
  // the children came as one string, which real LuCI puts in as HTML
  bare: boolean;
}

function walk(node: Node | string, found: Node[] = []): Node[] {
  if (typeof node === 'string') return found;
  found.push(node);
  node.children.forEach((child) => walk(child, found));
  return found;
}

const byClass = (root: Node, name: string) =>
  walk(root).filter((node) =>
    String(node.attr.class ?? '')
      .split(' ')
      .includes(name),
  );

const CHIP = 'pdk_dashboard-page__outbound-grid__item__block';
const BUTTON = 'pdk_dashboard-page__outbound-grid__item__check-button';
const TILE = 'pdk_dashboard-page__outbound-grid__item';
const FOOTER = 'pdk_dashboard-page__outbound-grid__item__footer';

const outbound = (
  code: string,
  change: Partial<Podkop.Outbound> = {},
): Podkop.Outbound => ({
  code,
  displayName: code,
  latency: 100,
  type: 'VLESS',
  selected: false,
  inUse: false,
  ...change,
});

function render(
  outbounds: Podkop.Outbound[],
  detect: Partial<IDetectWidget> = {},
  rule: Partial<Podkop.OutboundGroup> = {},
  latencyNow?: Record<string, number>,
) {
  const checks: ISectionChecks = {
    detect: {
      verdicts: {},
      servers: {},
      staleCures: 0,
      requested: {},
      probing: '',
      queued: [],
      noprobe: [],
      batch: null,
      ...detect,
    },
    onShowVerdict: vi.fn(),
    onCheckServer: vi.fn(),
    onCheckProblems: vi.fn(),
    onCancelChecks: vi.fn(),
  };
  const onChooseOutbound = vi.fn();
  const root = renderDefaultState({
    loading: false,
    failed: false,
    section: {
      withTagSelect: true,
      code: 'main-out',
      displayName: 'main',
      outbounds,
      ...rule,
    },
    onTestLatency: () => {},
    onChooseOutbound,
    latencyFetching: false,
    latencyNow,
    checks,
  }) as unknown as Node;
  return { root, checks, onChooseOutbound };
}

const click = (node: Node) => {
  const event = { stopPropagation: vi.fn() };
  (node.attr.click as (event: unknown) => void)(event);
  return event;
};

describe('the tile of a server', () => {
  beforeAll(() => {
    vi.stubGlobal(
      'E',
      (
        tag: string,
        attr: Record<string, unknown> | null,
        children?: (Node | string)[] | Node | string,
      ): Node => ({
        tag,
        attr: attr ?? {},
        children:
          children === undefined
            ? []
            : Array.isArray(children)
              ? children
              : [children],
        bare: typeof children === 'string',
      }),
    );
  });

  it('keeps the median and shows the result of the last test beside it', () => {
    const NOW = 'pdk_dashboard-page__outbound-grid__item__latency-now';
    const text = (node: Node) =>
      walk(node)
        .flatMap((n) => n.children.filter((c) => typeof c === 'string'))
        .join(' ');
    const before = render([outbound('a', { latency: 183 })]).root;
    expect(byClass(before, NOW)).toHaveLength(0);
    const { root } = render(
      [outbound('a', { latency: 183 }), outbound('b', { latency: 0 })],
      {},
      {},
      { a: 241, b: 0 },
    );
    const [tileA, tileB] = byClass(root, TILE);
    expect(text(tileA)).toContain('183ms');
    expect(text(byClass(tileA, NOW)[0])).toContain('241');
    expect(text(byClass(tileB, NOW)[0])).toContain('no answer');
  });

  it('has a check button that does not choose the server', () => {
    const server = outbound('a');
    const { root, checks, onChooseOutbound } = render([server]);
    const [button] = byClass(root, BUTTON);
    expect(button.attr.disabled).toBeNull();
    expect(click(button).stopPropagation).toHaveBeenCalled();
    expect(checks.onCheckServer).toHaveBeenCalledWith(server);
    expect(onChooseOutbound).not.toHaveBeenCalled();
  });

  it('has a real chip that opens its window and does not choose the server', () => {
    const server = outbound('a');
    const { root, checks } = render([server], {
      verdicts: { a: { block: 'limit', source: 'passive', kb: 18 } },
    });
    const [chip] = byClass(root, CHIP);
    expect(chip.tag).toBe('button');
    expect(chip.attr.class).toContain(`${CHIP}--warn`);
    expect(chip.attr.style).toBeUndefined();
    expect(click(chip).stopPropagation).toHaveBeenCalled();
    expect(checks.onShowVerdict).toHaveBeenCalledWith(server);
  });

  it('keeps the row out of the footer', () => {
    const { root } = render([outbound('a')], {
      verdicts: { a: { block: 'limit', source: 'passive', kb: 18 } },
    });
    const [footer] = byClass(root, FOOTER);
    expect(byClass(footer, CHIP)).toHaveLength(0);
    expect(byClass(footer, BUTTON)).toHaveLength(0);
  });

  it('does not let a tap on the row choose the server', () => {
    const { root } = render([outbound('a')], { probing: 'a' });
    const [row] = byClass(
      root,
      'pdk_dashboard-page__outbound-grid__item__check',
    );
    expect(click(row).stopPropagation).toHaveBeenCalled();
  });

  it('tells its tag and section', () => {
    const { root } = render([outbound('a')]);
    expect(byClass(root, TILE)[0].attr['data-tag']).toBe('a');
    expect(root.attr['data-section']).toBe('main-out');
  });

  it('never puts what comes from a link or the Clash API in as HTML', () => {
    const name = '<img src=x onerror=alert(1)>';
    const { root } = render(
      [outbound(name, { displayName: name, type: name })],
      { verdicts: { [name]: { block: 'limit', source: 'passive', kb: 18 } } },
    );
    const texts = walk(root)
      .filter((node) => node.bare)
      .flatMap((node) => node.children);
    expect(texts.length).toBeGreaterThan(0);
    expect(texts).not.toContain(name);
    expect(
      walk(root).filter((node) => node.children.includes(name)),
    ).toHaveLength(2);
  });

  it('disables the button while the check is under way', () => {
    for (const detect of [
      { probing: 'a' },
      { queued: ['a'] },
      { requested: { a: 1 } },
    ]) {
      const { root } = render([outbound('a')], detect);
      expect(byClass(root, BUTTON)[0].attr.disabled).toBe('disabled');
    }
  });

  it('has neither button nor row where no check goes', () => {
    const { root } = render(
      [
        outbound('main-urltest-out', { type: 'URLTest' }),
        outbound('direct-out', { type: 'Direct' }),
        outbound('block', { type: 'Reject' }),
        outbound('a via b'),
      ],
      { noprobe: ['a via b'] },
    );
    expect(byClass(root, BUTTON)).toHaveLength(0);
    expect(
      byClass(root, 'pdk_dashboard-page__outbound-grid__item__check'),
    ).toHaveLength(0);
  });

  it('shows the chip of a server it cannot check, with no button', () => {
    const { root } = render([outbound('a via b')], {
      noprobe: ['a via b'],
      verdicts: {
        'a via b': { block: 'limit', source: 'passive', kb: 18 },
      },
    });
    expect(byClass(root, CHIP)).toHaveLength(1);
    expect(byClass(root, BUTTON)).toHaveLength(0);
  });
});

describe('the header of a section', () => {
  const PROBLEMS = 'dashboard-sections-grid-item-check-problems';
  const PROGRESS = 'dashboard-sections-grid-item-check-progress';
  const CANCEL = 'dashboard-sections-grid-item-check-cancel';

  it('offers the check only when there is a problem', () => {
    expect(byClass(render([outbound('a')]).root, PROBLEMS)).toHaveLength(0);
    const { root, checks } = render([outbound('a', { latency: 0 })]);
    const [button] = byClass(root, PROBLEMS);
    expect(button.attr.disabled).toBeNull();
    expect(button.attr.title).toBeNull();
    click(button);
    expect(checks.onCheckProblems).toHaveBeenCalled();
  });

  it('ends a press with a chip and no problem to check over a weak verdict', () => {
    const { root } = render([outbound('a', { latency: 0 })], {
      verdicts: {
        a: { block: 'unknown', source: 'active', notes: ['inconclusive'] },
      },
    });
    const [chip] = byClass(root, CHIP);
    expect(chip.children).toEqual(['details']);
    expect(String(chip.attr.class)).toContain(`${CHIP}--neutral`);
    expect(byClass(root, PROBLEMS)).toHaveLength(0);
    // the tile keeps its own button
    expect(byClass(root, BUTTON)).toHaveLength(1);
  });

  it('shows the progress and the way to cancel', () => {
    const { root, checks } = render([outbound('a'), outbound('b')], {
      batch: { section: 'main-out', tags: ['a', 'b'] },
      queued: ['b'],
    });
    expect(byClass(root, PROGRESS)[0].children).toEqual(['1 of 2']);
    expect(byClass(root, PROGRESS)[0].attr['aria-live']).toBe('polite');
    expect(byClass(root, PROBLEMS)).toHaveLength(0);
    click(byClass(root, CANCEL)[0]);
    expect(checks.onCancelChecks).toHaveBeenCalled();
  });

  it('says when the queue took only the first of the tiles', () => {
    const { root } = render([outbound('a'), outbound('b')], {
      batch: { section: 'main-out', tags: ['a', 'b'], found: 70 },
      queued: ['b'],
    });
    expect(byClass(root, PROGRESS)[0].children).toEqual([
      '1 of 2, first 64 of 70',
    ]);
  });

  it('shows what waits when the progress is not known here', () => {
    const { root } = render([outbound('a'), outbound('b')], {
      queued: ['a', 'b', 'elsewhere'],
    });
    expect(byClass(root, PROGRESS)[0].children).toEqual(['Queued: 2']);
    expect(byClass(root, CANCEL)).toHaveLength(1);
  });

  it('holds the check of a section while another one runs', () => {
    const { root } = render([outbound('a', { latency: 0 })], {
      batch: { section: 'other-out', tags: ['x'] },
    });
    expect(byClass(root, PROBLEMS)[0].attr.disabled).toBe('disabled');
    expect(byClass(root, PROBLEMS)[0].attr.title).toBeTruthy();
    expect(byClass(root, PROGRESS)).toHaveLength(0);
  });
});

describe('the tiers of a rule', () => {
  const CELL = 'pdk_dashboard-page__outbound-grid__cell';
  const TIER = 'pdk_dashboard-page__outbound-grid__tier';
  const ROUTE = 'pdk_dashboard-page__outbound-section__route';
  const AUTO = 'dashboard-sections-grid-item-auto';
  const tiered = [
    outbound('a', { tier: 0 }),
    outbound('b', { tier: 0 }),
    outbound('c', { tier: 1, active: true }),
    outbound('d', { tier: 1, pick: true }),
    outbound('direct-out', { tier: 2, type: 'Direct', selectable: false }),
  ];
  const tiers = ['Fastest', 'Fallback 1 · sub', 'Fallback 2'];

  it('puts each tile on the tint of its tier, two in turn, and names a tier over its first tile', () => {
    const { root } = render(tiered, {}, { tiers });
    const cells = byClass(root, CELL);
    expect(
      cells.map((cell) => String(cell.attr.class).split('--tint-')[1]),
    ).toEqual(['0', '0', '1', '1', '0']);
    expect(cells.map((cell) => byClass(cell, TIER).length)).toEqual([
      1, 0, 1, 0, 1,
    ]);
    expect(byClass(root, TIER).map((name) => name.children[0])).toEqual(tiers);
  });

  it('keeps the plain grid for a rule without fallbacks', () => {
    const { root } = render([outbound('a'), outbound('b')], {}, { tiers: [] });
    expect(byClass(root, CELL)).toHaveLength(0);
    expect(byClass(root, TILE)).toHaveLength(2);
  });

  it('marks the server in use and the choice of a fallback, and pins only what the selector offers', () => {
    const { root, onChooseOutbound } = render(tiered, {}, { tiers });
    const tiles = byClass(root, TILE);
    expect(
      tiles.map((tile) => String(tile.attr.class).includes('--active')),
    ).toEqual([false, false, true, false, false]);
    expect(
      tiles.map((tile) => String(tile.attr.class).includes('--pick')),
    ).toEqual([false, false, false, true, false]);
    click(tiles[4]);
    expect(onChooseOutbound).not.toHaveBeenCalled();
    expect(String(tiles[4].attr.class)).not.toContain('--selectable');
    click(tiles[3]);
    expect(onChooseOutbound).toHaveBeenCalledWith('main-out', 'd');
  });

  it('tells where the URL test went, beside the name of the rule', () => {
    const route: Podkop.OutboundRoute = {
      mode: 'auto',
      tier: 1,
      code: 'c',
      displayName: 'C',
      latency: 140,
    };
    const { root } = render(
      tiered,
      {},
      { tiers, route, auto: 'main-urltest-out' },
    );
    const [line] = byClass(root, ROUTE);
    expect(line.children).toEqual(['Fastest → Fallback 1: C · 140ms']);
    expect(String(line.attr.class)).toContain('--warning');
    expect(byClass(root, AUTO)).toHaveLength(0);
  });

  it('tells a pinned server and gives the way back to the URL test', () => {
    const route: Podkop.OutboundRoute = {
      mode: 'manual',
      tier: 1,
      code: 'c',
      displayName: 'C',
      latency: 0,
    };
    const { root, onChooseOutbound } = render(
      tiered,
      {},
      { tiers, route, auto: 'main-urltest-out' },
    );
    expect(byClass(root, ROUTE)[0].children).toEqual(['Manual: C · N/A']);
    const [back] = byClass(root, AUTO);
    click(back);
    expect(onChooseOutbound).toHaveBeenCalledWith(
      'main-out',
      'main-urltest-out',
    );
  });

  it('tells a block fallback in use as refusing', () => {
    const route: Podkop.OutboundRoute = {
      mode: 'auto',
      tier: 2,
      code: 'block',
      displayName: 'Block',
      latency: 0,
    };
    const { root } = render(
      tiered,
      {},
      { tiers, route, auto: 'main-urltest-out' },
    );
    const [line] = byClass(root, ROUTE);
    expect(String(line.attr.class)).toContain('--error');
    expect(String(line.attr.class)).not.toContain('--warning');
  });

  it('says nothing of the route of a rule of one server', () => {
    const route: Podkop.OutboundRoute = {
      mode: 'single',
      tier: 0,
      code: 'a',
      displayName: 'A',
      latency: 90,
    };
    const { root } = render([outbound('a', { active: true })], {}, { route });
    expect(byClass(root, ROUTE)).toHaveLength(0);
  });
});

describe('the cure badge of a tile', () => {
  const CURE = 'pdk_dashboard-page__outbound-grid__item__cure';
  beforeAll(() => {
    vi.stubGlobal(
      'E',
      (
        tag: string,
        attr: Record<string, unknown> | null,
        children?: (Node | string)[] | Node | string,
      ): Node => ({
        tag,
        attr: attr ?? {},
        children:
          children === undefined
            ? []
            : Array.isArray(children)
              ? children
              : [children],
        bare: typeof children === 'string',
      }),
    );
  });
  const text = (node: Node) =>
    node.children.filter((c): c is string => typeof c === 'string').join('');

  it('renders a mask badge with the sni that opens the window, not choosing the server', () => {
    const server = outbound('a', {
      cure: { kind: 'spoof', sni: 'packagist.com' },
    });
    const { root, checks, onChooseOutbound } = render([server]);
    const nodes = byClass(root, CURE);
    expect(nodes).toHaveLength(1);
    expect(text(nodes[0])).toContain('packagist.com');
    const event = click(nodes[0]);
    expect(event.stopPropagation).toHaveBeenCalled();
    expect(checks.onShowVerdict).toHaveBeenCalledWith(server);
    expect(onChooseOutbound).not.toHaveBeenCalled();
  });

  it('renders a record_fragment badge', () => {
    const { root } = render([
      outbound('a', { cure: { kind: 'record_fragment' } }),
    ]);
    const nodes = byClass(root, CURE);
    expect(nodes).toHaveLength(1);
    expect(text(nodes[0])).toContain('record fragment');
  });

  it('renders no badge without a cure, and keeps the chip/button rows', () => {
    const { root } = render([outbound('a')], {
      verdicts: { a: { block: 'limit', source: 'active', kb: 18 } },
    });
    expect(byClass(root, CURE)).toHaveLength(0);
    expect(byClass(root, CHIP)).toHaveLength(1);
    expect(byClass(root, BUTTON)).toHaveLength(1);
  });
});
