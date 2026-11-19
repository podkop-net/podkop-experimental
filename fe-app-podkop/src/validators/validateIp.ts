import { ValidationResult } from './types';

export function validateIPV4(ip: string): ValidationResult {
  const ipRegex =
    /^(?:(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$/;

  if (ipRegex.test(ip)) {
    return { valid: true, message: _('Valid') };
  }

  return { valid: false, message: _('Invalid IP address') };
}

// An IPv6 address in its text form: eight groups of up to four hex digits, or fewer with one
// "::". No zone ("%eth0") and no IPv4 tail ("::ffff:1.2.3.4"), as the backend takes them.
export function isIPv6(value: string): boolean {
  if (!value || !value.includes(':') || value.includes('%')) {
    return false;
  }
  const halves = value.split('::');
  if (halves.length > 2) {
    return false;
  }
  const groups = (text: string) => (text === '' ? [] : text.split(':'));
  const all = [
    ...groups(halves[0]),
    ...(halves.length === 2 ? groups(halves[1]) : []),
  ];
  if (!all.every((group) => /^[0-9a-fA-F]{1,4}$/.test(group))) {
    return false;
  }
  return halves.length === 2 ? all.length <= 7 : all.length === 8;
}

// isUnspecifiedIPv6 tells "::" and its longer forms (all groups zero).
export function isUnspecifiedIPv6(value: string): boolean {
  return (
    isIPv6(value) &&
    value
      .split(':')
      .filter(Boolean)
      .every((group) => /^0+$/.test(group))
  );
}

export function validateIPV6(ip: string): ValidationResult {
  if (isIPv6(ip)) {
    return { valid: true, message: _('Valid') };
  }

  return { valid: false, message: _('Invalid IPv6 address') };
}

// An address of either family.
export function validateIP(ip: string): ValidationResult {
  if (validateIPV4(ip).valid || isIPv6(ip)) {
    return { valid: true, message: _('Valid') };
  }

  return { valid: false, message: _('Invalid IP address') };
}
