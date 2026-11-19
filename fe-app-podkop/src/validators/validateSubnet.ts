import { ValidationResult } from './types';
import { isIPv6, isUnspecifiedIPv6, validateIPV4 } from './validateIp';

// An address or a subnet of IPv4 or IPv6 (the lists of a rule).
export function validateSubnet(value: string): ValidationResult {
  if (value.includes(':')) {
    return validateSubnet6(value);
  }
  return validateSubnet4(value);
}

// An address or a subnet of IPv4 only (the devices a rule takes whole).
export function validateSubnet4(value: string): ValidationResult {
  // Must be in form X.X.X.X or X.X.X.X/Y
  const subnetRegex = /^(\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?$/;

  if (!subnetRegex.test(value)) {
    return {
      valid: false,
      message: _('Invalid format. Use X.X.X.X or X.X.X.X/Y'),
    };
  }

  const [ip, cidr] = value.split('/');

  if (ip === '0.0.0.0') {
    return { valid: false, message: _('IP address 0.0.0.0 is not allowed') };
  }

  const ipCheck = validateIPV4(ip);
  if (!ipCheck.valid) {
    return ipCheck;
  }

  // Validate CIDR if present
  if (cidr) {
    const cidrNum = parseInt(cidr, 10);

    if (cidrNum < 0 || cidrNum > 32) {
      return {
        valid: false,
        message: _('CIDR must be between 0 and 32'),
      };
    }
  }

  return { valid: true, message: _('Valid') };
}

function validateSubnet6(value: string): ValidationResult {
  const parts = value.split('/');
  if (parts.length > 2 || !isIPv6(parts[0])) {
    return {
      valid: false,
      message: _(
        'Invalid format. Use X.X.X.X, X.X.X.X/Y, an IPv6 address or IPv6/Y',
      ),
    };
  }
  if (isUnspecifiedIPv6(parts[0])) {
    return { valid: false, message: _('IP address :: is not allowed') };
  }
  if (parts.length === 2) {
    if (!/^\d{1,3}$/.test(parts[1]) || parseInt(parts[1], 10) > 128) {
      return {
        valid: false,
        message: _('The prefix length of IPv6 must be between 0 and 128'),
      };
    }
  }
  return { valid: true, message: _('Valid') };
}
