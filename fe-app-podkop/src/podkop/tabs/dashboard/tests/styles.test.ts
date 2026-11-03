import { describe, expect, it } from 'vitest';
import { styles } from '../styles';

// What the chip declares; how it looks on a narrow tile takes a browser. The tile itself has
// overflow-wrap: anywhere for the long names of servers, and a chip inherits that.
const chip =
  /button\.pdk_dashboard-page__outbound-grid__item__block \{([^}]*)\}/.exec(
    styles,
  )?.[1];

describe('the chip of a verdict', () => {
  it('wraps between words only', () => {
    expect(chip).toMatch(/white-space: normal;/);
    expect(chip).toMatch(/overflow-wrap: normal;/);
    expect(chip).toMatch(/word-break: normal;/);
  });

  it('stays in the tile', () => {
    expect(chip).toMatch(/max-width: 100%;/);
    expect(chip).toMatch(/overflow: hidden;/);
  });

  // !important: the theme on a phone sets the font of every button so
  it('takes a smaller font in a narrow tile, the plain one without cqi', () => {
    expect(chip).toMatch(
      /font-size: 12px !important;\s+font-size: clamp\(9px, .*cqi.*, 12px\) !important;/,
    );
    expect(styles).toMatch(/__item__check \{\s+container-type: inline-size;/);
  });
});
