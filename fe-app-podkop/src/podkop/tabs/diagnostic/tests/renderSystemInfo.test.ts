import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { renderSystemInfo } from '../partials/renderSystemInfo';

interface Node {
  tag: string;
  attr: Record<string, unknown>;
  children: (Node | string)[];
}

const TAG = 'pdk_diagnostic-page__right-bar__system-info__row__tag';

function walk(node: Node | string, found: Node[] = []): Node[] {
  if (typeof node === 'string') return found;
  found.push(node);
  node.children.forEach((child) => walk(child, found));
  return found;
}

function tagClasses(kind?: 'warning' | 'success' | 'neutral') {
  const root = renderSystemInfo({
    items: [
      {
        key: 'Podkop',
        value: '0.8.20.1',
        ...(kind ? { tag: { label: 'label', kind } } : {}),
      },
    ],
  }) as unknown as Node;
  const tag = walk(root).find((node) =>
    String(node.attr.class ?? '')
      .split(' ')
      .includes(TAG),
  );
  return String(tag?.attr.class ?? '').split(' ');
}

describe('renderSystemInfo', () => {
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
      }),
    );
  });

  afterAll(() => vi.unstubAllGlobals());

  it.each(['warning', 'success', 'neutral'] as const)(
    'gives a %s tag its own look',
    (kind) => {
      expect(tagClasses(kind)).toEqual([TAG, `${TAG}--${kind}`]);
    },
  );

  it('gives a row without a tag only the base class', () => {
    expect(tagClasses()).toEqual([TAG]);
  });
});
