import { describe, expect, it } from 'vitest';
import {
  validateMixedProxyPassword,
  validateMixedProxyUser,
} from '../validateMixedProxyLogin';

const longest = 'a'.repeat(255);

describe('validateMixedProxyUser', () => {
  it.each([
    ['empty: no login', ''],
    ['a name', 'podkop'],
    ['signs', "!#$%&'()*+,-./;<=>?@[\\]^_`{|}~"],
    ['255 characters', longest],
  ])('takes %s', (_desc, value) => {
    expect(validateMixedProxyUser(value).valid).toBe(true);
  });

  it.each([
    [
      'a space',
      'pdk user',
      'Latin letters, digits and signs only, without spaces',
    ],
    [
      'a tab',
      'pdk\tuser',
      'Latin letters, digits and signs only, without spaces',
    ],
    ['DEL', 'pdk\x7f', 'Latin letters, digits and signs only, without spaces'],
    [
      'a Cyrillic letter',
      'юзер',
      'Latin letters, digits and signs only, without spaces',
    ],
    ['256 characters', longest + 'a', 'At most 255 characters'],
    ['a colon', 'pdk:user', 'No “:” in the user name: HTTP cannot send it'],
  ])('refuses %s', (_desc, value, message) => {
    const result = validateMixedProxyUser(value);
    expect(result.valid).toBe(false);
    expect(result.message).toBe(message);
  });
});

describe('validateMixedProxyPassword', () => {
  it.each([
    ['both empty: no login', '', ''],
    ['8 characters', 'Zx9-secr', 'podkop'],
    ['a colon', 'Zx9:secret', 'podkop'],
    ['every sign', '!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~', 'podkop'],
    ['255 characters', longest, 'podkop'],
  ])('takes %s', (_desc, value, user) => {
    expect(validateMixedProxyPassword(value, user).valid).toBe(true);
  });

  it.each([
    [
      'a user name alone',
      '',
      'podkop',
      'Set the password too, or clear the user name',
    ],
    [
      'a password alone',
      'Zx9-secret',
      '',
      'Set the user name too, or clear the password',
    ],
    ['7 characters', 'Zx9-sec', 'podkop', 'At least 8 characters'],
    ['256 characters', longest + 'a', 'podkop', 'At most 255 characters'],
    [
      'a space',
      'Zx9 secret',
      'podkop',
      'Latin letters, digits and signs only, without spaces',
    ],
    [
      'a space at the end',
      'Zx9-secret ',
      'podkop',
      'Latin letters, digits and signs only, without spaces',
    ],
    [
      'a Cyrillic letter',
      'пароль-пароль',
      'podkop',
      'Latin letters, digits and signs only, without spaces',
    ],
  ])('refuses %s', (_desc, value, user, message) => {
    const result = validateMixedProxyPassword(value, user);
    expect(result.valid).toBe(false);
    expect(result.message).toBe(message);
  });

  it('takes a short password the settings have already, as the backend does', () => {
    expect(validateMixedProxyPassword('1234', 'podkop', true).valid).toBe(true);
    expect(validateMixedProxyPassword('1234', 'podkop', false).valid).toBe(
      false,
    );
    // the rest is asked of it still
    expect(validateMixedProxyPassword('12 34', 'podkop', true).valid).toBe(
      false,
    );
    expect(validateMixedProxyPassword('1234', '', true).valid).toBe(false);
  });
});
