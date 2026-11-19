import { describe, it, expect } from 'vitest';
import { isIPv6, validateIP, validateIPV6 } from '../validateIp';
import { validateSubnet, validateSubnet4 } from '../validateSubnet';
import { validateDNS } from '../validateDns';

const validIPv6 = [
  '::1',
  '::',
  '2001:db8::1',
  '2001:0db8:0000:0000:0000:ff00:0042:8329',
  'fe80::1',
  '2a02:6b8::feed:0ff',
  '1::',
  '1:2:3:4:5:6:7::',
  '::2:3:4:5:6:7:8',
];

const invalidIPv6 = [
  '',
  '2001:db8::1::2',
  '2001:db8:1',
  '1:2:3:4:5:6:7:8:9',
  '1:2:3:4:5:6:7::8',
  '12345::1',
  'g::1',
  ':1',
  '1:',
  'fe80::1%eth0',
  '::ffff:1.2.3.4',
  '1.2.3.4',
];

describe('isIPv6', () => {
  it.each(validIPv6)('valid %s', (value) => {
    expect(isIPv6(value)).toBe(true);
    expect(validateIPV6(value).valid).toBe(true);
    expect(validateIP(value).valid).toBe(true);
  });
  it.each(invalidIPv6)('invalid %s', (value) => {
    expect(isIPv6(value)).toBe(false);
    expect(validateIPV6(value).valid).toBe(false);
  });
  it('validateIP takes IPv4 too', () => {
    expect(validateIP('192.168.1.1').valid).toBe(true);
    expect(validateIP('300.1.1.1').valid).toBe(false);
  });
});

describe('validateSubnet with IPv6', () => {
  it.each([
    '2001:db8::/32',
    '2001:67c:4e8::/48',
    '2001:b28:f23d::1',
    '2001:b28:f23d::1/128',
    '2000::/3',
  ])('valid %s', (value) => {
    expect(validateSubnet(value).valid).toBe(true);
  });
  it.each([
    '::',
    '::/0',
    '0:0:0:0:0:0:0:0/0',
    '2001:db8::/129',
    '2001:db8::/-1',
    '2001:db8::/abc',
    '2001:db8::/32/1',
    '2001:db8:::/32',
    '2001:db8::/032',
  ])('invalid %s', (value) => {
    expect(validateSubnet(value).valid).toBe(false);
  });
  it('validateSubnet4 refuses IPv6', () => {
    expect(validateSubnet4('2001:db8::/32').valid).toBe(false);
    expect(validateSubnet4('192.168.1.0/24').valid).toBe(true);
  });
});

describe('validateDNS with IPv6', () => {
  it.each([
    '[2001:4860:4860::8888]:853',
    '[2001:4860:4860::8888]',
    '2001:4860:4860::8888',
    '[2a10:50c0::ad1:ff]:443/dns-query',
    '[2a10:50c0::ad1:ff]/dns-query',
    '2a10:50c0::ad1:ff/dns-query',
  ])('valid %s', (value) => {
    expect(validateDNS(value).valid).toBe(true);
  });
  it.each([
    '[2001:4860:4860::8888',
    '[2001:4860:4860::8888]:0',
    '[2001:4860:4860::8888]:70000',
    '[1.2.3.4]:53',
    '[dns.example.com]:853',
    '2001:4860:4860::8888:853:1:2:3',
  ])('invalid %s', (value) => {
    expect(validateDNS(value).valid).toBe(false);
  });
});
