import { describe, expect, it } from 'vitest';
import { generateProxyPassword } from '../generateProxyPassword';
import { validateMixedProxyPassword } from '../../validators/validateMixedProxyLogin';

describe('generateProxyPassword', () => {
  it('gives 16 letters and digits that the page takes', () => {
    const password = generateProxyPassword();
    expect(password).toMatch(/^[A-Za-z0-9]{16}$/);
    expect(validateMixedProxyPassword(password, 'podkop').valid).toBe(true);
  });

  it('gives another password each time', () => {
    const drawn = new Set();
    for (let index = 0; index < 1000; index++) {
      drawn.add(generateProxyPassword());
    }
    expect(drawn.size).toBe(1000);
  });

  it('uses every sign, the last ones of the range too', () => {
    const signs = new Set(generateProxyPassword(4000));
    expect(signs.size).toBe(62);
  });
});
