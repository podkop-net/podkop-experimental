import { describe, it, expect } from 'vitest';
import {
  isUniqueLocal,
  subnetContains,
  validateDevice,
} from '../validateDevice';

// as the backend's model.ParseDevices takes them
const validDevices = [
  ['IPv4 address', '192.168.1.50'],
  ['IPv4 subnet', '192.168.1.0/24'],
  ['IPv4 subnet of one', '192.168.1.50/32'],
  ['IPv4 subnet not masked', '192.168.1.7/24'],
  ['IPv6 address', '2001:db8:1::50'],
  ['IPv6 subnet', '2001:db8:1::/64'],
  ['IPv6 subnet of one', '2001:db8:1::50/128'],
  ['IPv6 unique local (warned of, not refused)', 'fd00::50'],
];

const invalidDevices = [
  ['a word', 'word'],
  ['empty', ''],
  ['leading zero in an octet', '192.168.1.050'],
  ['leading zero in an IPv4 prefix length', '192.168.1.0/08'],
  ['leading zero in an IPv6 prefix length', '2001:db8::/064'],
  ['IPv4 /0', '1.2.3.4/0'],
  ['IPv4 0.0.0.0', '0.0.0.0'],
  ['IPv4 0.0.0.0/0', '0.0.0.0/0'],
  ['IPv6 /0', '2001:db8::/0'],
  ['IPv6 ::', '::'],
  ['IPv6 ::/0', '::/0'],
  ['a zone', 'fe80::1%eth0'],
  ['IPv6 link-local', 'fe80::1'],
  ['IPv6 link-local subnet', 'fe80::/64'],
  ['IPv4 in IPv6 form, dotted', '::ffff:192.168.1.50'],
  ['IPv4 in IPv6 form, hex', '::ffff:c0a8:132'],
  ['IPv4 prefix too long', '192.168.1.0/33'],
  ['IPv6 prefix too long', '2001:db8::/129'],
];

describe('validateDevice', () => {
  describe.each(validDevices)('Valid device: %s', (_desc, value) => {
    it(`returns {valid:true} for "${value}"`, () => {
      expect(validateDevice(value).valid).toBe(true);
    });
  });

  describe.each(invalidDevices)('Invalid device: %s', (_desc, value) => {
    it(`returns {valid:false} for "${value}"`, () => {
      expect(validateDevice(value).valid).toBe(false);
    });
  });

  it('tells why', () => {
    expect(validateDevice('10.0.0.0/0').message).toBe(
      'A subnet of the whole internet is no device',
    );
    expect(validateDevice('fe80::1').message).toContain('link-local');
    expect(validateDevice('192.168.1.0/08').message).toContain('leading zero');
  });
});

describe('subnetContains', () => {
  it.each([
    ['192.168.1.0/24', '192.168.1.50', true],
    ['192.168.1.50', '192.168.1.50', true],
    ['192.168.1.50/32', '192.168.1.50', true],
    ['192.168.1.0/24', '192.168.1.128/25', true],
    ['192.168.1.7/24', '192.168.1.200', true],
    ['192.168.1.128/25', '192.168.1.0/24', false],
    ['192.168.1.0/24', '192.168.2.1', false],
    ['192.168.1.50', '192.168.1.51', false],
    ['10.0.0.0/8', '10.255.255.255', true],
    ['2001:db8:1::/64', '2001:db8:1::50', true],
    ['2001:db8:1::/64', '2001:db8:1:0:ffff::1', true],
    ['2001:db8:1::/64', '2001:db8:1:1::1', false],
    ['2001:0db8:0001:0000:0000:0000:0000:0050', '2001:db8:1::50', true],
    ['::/0', '2001:db8::1', true],
    ['fc00::/7', 'fd12:3456::1', true],
    ['fc00::/7', 'fe80::1', false],
    // across the families: never
    ['0.0.0.0/0', '2001:db8::1', false],
    ['::/0', '192.168.1.50', false],
    ['::ffff:0:0/96', '192.168.1.50', false],
    // no address
    ['word', '192.168.1.50', false],
    ['192.168.1.0/24', 'word', false],
  ])('%s holds %s: %s', (outer, inner, expected) => {
    expect(subnetContains(outer, inner)).toBe(expected);
  });
});

describe('isUniqueLocal', () => {
  it('tells the unique local addresses of IPv6', () => {
    expect(isUniqueLocal('fd00::50')).toBe(true);
    expect(isUniqueLocal('fc00::/7')).toBe(true);
    expect(isUniqueLocal('fd12:3456::/64')).toBe(true);
    expect(isUniqueLocal('2001:db8::1')).toBe(false);
    expect(isUniqueLocal('192.168.1.50')).toBe(false);
    expect(isUniqueLocal('word')).toBe(false);
  });
});
