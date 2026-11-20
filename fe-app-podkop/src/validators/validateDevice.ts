import { ValidationResult } from './types';
import { isIPv6, validateIPV4 } from './validateIp';
import { validateSubnet } from './validateSubnet';

interface Prefix {
  // the address as a number, masked to the length
  bits: bigint;
  // 32 for IPv4, 128 for IPv6
  width: number;
  length: number;
}

// The bits of an address: an IPv4 one in dotted form, an IPv6 one as isIPv6 takes it ("::"
// expanded); null for no address.
function addressBits(address: string): { bits: bigint; width: number } | null {
  if (!address.includes(':')) {
    if (!validateIPV4(address).valid) return null;
    const bits = address
      .split('.')
      .reduce(
        (sum, octet) => (sum << BigInt(8)) | BigInt(Number(octet)),
        BigInt(0),
      );
    return { bits, width: 32 };
  }
  if (!isIPv6(address)) return null;
  const halves = address.split('::');
  const groups = (text: string) => (text === '' ? [] : text.split(':'));
  const head = groups(halves[0]);
  const tail = halves.length === 2 ? groups(halves[1]) : [];
  const all = [
    ...head,
    ...Array(8 - head.length - tail.length).fill('0'),
    ...tail,
  ];
  const bits = all.reduce(
    (sum, group) => (sum << BigInt(16)) | BigInt(parseInt(group, 16)),
    BigInt(0),
  );
  return { bits, width: 128 };
}

// An address or a subnet as a prefix; null for neither.
function parsePrefix(value: string): Prefix | null {
  const parts = String(value || '')
    .trim()
    .split('/');
  if (parts.length > 2) return null;
  const address = addressBits(parts[0]);
  if (!address) return null;
  let length = address.width;
  if (parts.length === 2) {
    if (!/^(0|[1-9]\d{0,2})$/.test(parts[1])) return null;
    length = Number(parts[1]);
    if (length > address.width) return null;
  }
  const host = (BigInt(1) << BigInt(address.width - length)) - BigInt(1);
  return { bits: address.bits & ~host, width: address.width, length };
}

// subnetContains tells whether the address or subnet inner lies within the address or subnet
// outer, as the backend's PrefixWithin does: of the same family, no shorter, inside it.
export function subnetContains(outer: string, inner: string): boolean {
  const big = parsePrefix(outer);
  const small = parsePrefix(inner);
  if (
    !big ||
    !small ||
    big.width !== small.width ||
    big.length > small.length
  ) {
    return false;
  }
  const host = (BigInt(1) << BigInt(big.width - big.length)) - BigInt(1);
  return (small.bits & ~host) === big.bits;
}

const LINK_LOCAL = 'fe80::/10';
const MAPPED = '::ffff:0:0/96';
const UNIQUE_LOCAL = 'fc00::/7';

// An item of "Only for devices": an IPv4 or IPv6 address or subnet, as the backend
// (model.ParseDevices) takes one. Not a subnet of the whole internet, nor a link-local address
// of IPv6, nor an IPv4 address in IPv6 form; the length of a prefix without a leading zero.
export function validateDevice(value: string): ValidationResult {
  const base = validateSubnet(value);
  if (!base.valid) {
    return base;
  }
  const [address, length] = value.split('/');
  if (length !== undefined && !/^(0|[1-9]\d{0,2})$/.test(length)) {
    return {
      valid: false,
      message: _('The prefix length is written without a leading zero'),
    };
  }
  if (length === '0') {
    return {
      valid: false,
      message: _('A subnet of the whole internet is no device'),
    };
  }
  if (address.includes(':')) {
    if (subnetContains(MAPPED, address)) {
      return {
        valid: false,
        message: _('An IPv4 address in IPv6 form: write it as IPv4'),
      };
    }
    if (subnetContains(LINK_LOCAL, address)) {
      return {
        valid: false,
        message: _(
          'A link-local address (fe80::) is never the source of a connection to the internet',
        ),
      };
    }
  }
  return { valid: true, message: _('Valid') };
}

// isUniqueLocal tells an item of "Only for devices" that is a unique local address of IPv6
// (fc00::/7): a device sends from it to the internet only when it has no global IPv6 address and
// the router translates its IPv6 (NAT66), so it rarely takes anything.
export function isUniqueLocal(value: string): boolean {
  const address = String(value || '').split('/')[0];
  return address.includes(':') && subnetContains(UNIQUE_LOCAL, address);
}
