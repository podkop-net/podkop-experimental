import { afterEach, describe, expect, it, vi } from 'vitest';
import { keepFocus } from '../helpers/keepFocus';

const CHECK = 'pdk_dashboard-page__outbound-grid__item__check-button';
const CANCEL = 'dashboard-sections-grid-item-check-cancel';

// the part of an element keepFocus reads
const control = (
  name: string,
  section: string,
  tag: string | null,
  disabled = false,
) => ({
  disabled,
  focus: vi.fn(),
  classList: { contains: (other: string) => other === name },
  closest: (selector: string) => {
    const value = selector === '[data-section]' ? section : tag;
    return value === null ? null : { getAttribute: () => value };
  },
  name,
});

type Control = ReturnType<typeof control>;

const grid = (first: Control[], next: Control[]) => {
  let elements = first;
  return {
    contains: (element: Control) => first.includes(element),
    getElementsByClassName: (name: string) =>
      elements.filter((element) => element.name === name),
    rebuild: () => {
      elements = next;
    },
  };
};

function run(focused: unknown, first: Control[], next: Control[]) {
  vi.stubGlobal('document', { activeElement: focused });
  const container = grid(first, next);
  const rebuild = vi.fn(container.rebuild);
  keepFocus(container as unknown as Element, rebuild);
  expect(rebuild).toHaveBeenCalledOnce();
}

describe('keepFocus', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('gives the focus to the same control of the same tile', () => {
    const old = control(CHECK, 'main-out', 'a');
    const other = control(CHECK, 'main-out', 'b');
    const same = control(CHECK, 'main-out', 'a');
    run(old, [old], [other, same]);
    expect(same.focus).toHaveBeenCalledWith({ preventScroll: true });
    expect(other.focus).not.toHaveBeenCalled();
  });

  it('tells one tag in two sections apart', () => {
    const old = control(CHECK, 'two-out', 'a');
    const inOne = control(CHECK, 'one-out', 'a');
    const inTwo = control(CHECK, 'two-out', 'a');
    run(old, [old], [inOne, inTwo]);
    expect(inTwo.focus).toHaveBeenCalled();
    expect(inOne.focus).not.toHaveBeenCalled();
  });

  it('finds a control of the header of a section', () => {
    const old = control(CANCEL, 'main-out', null);
    const same = control(CANCEL, 'main-out', null);
    run(old, [old], [same]);
    expect(same.focus).toHaveBeenCalled();
  });

  it('leaves a control that has gone or is disabled', () => {
    const old = control(CHECK, 'main-out', 'a');
    const disabled = control(CHECK, 'main-out', 'a', true);
    run(old, [old], [disabled]);
    expect(disabled.focus).not.toHaveBeenCalled();
    run(old, [old], []);
  });

  it('leaves the focus that is outside the grid', () => {
    const outside = control(CHECK, 'main-out', 'a');
    const same = control(CHECK, 'main-out', 'a');
    run(outside, [], [same]);
    expect(same.focus).not.toHaveBeenCalled();
  });

  it('leaves what is not a control it knows, or no focus at all', () => {
    const other = control('something-else', 'main-out', 'a');
    const same = control('something-else', 'main-out', 'a');
    run(other, [other], [same]);
    expect(same.focus).not.toHaveBeenCalled();
    run(null, [], []);
  });
});
