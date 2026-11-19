import { validateDomain } from './validateDomain';
import { isIPv6, validateIPV4 } from './validateIp';
import { ValidationResult } from './types';

function invalidDNS(): ValidationResult {
  return {
    valid: false,
    message: _(
      'Invalid DNS server format. Examples: 8.8.8.8, [2001:4860:4860::8888]:853, dns.example.com or dns.example.com/nicedns for DoH',
    ),
  };
}

export function validateDNS(value: string): ValidationResult {
  if (!value) {
    return { valid: false, message: _('DNS server address cannot be empty') };
  }

  // IPv6: in brackets, with a port and a path or without ("[2001:db8::1]:853"), or bare
  // without a port ("2001:db8::1")
  const bracketed = value.match(/^\[([^\]]*)\](?::(\d{1,5}))?(\/.*)?$/);
  if (bracketed) {
    const port = bracketed[2] === undefined ? 1 : parseInt(bracketed[2], 10);
    return isIPv6(bracketed[1]) && port >= 1 && port <= 65535
      ? { valid: true, message: _('Valid') }
      : invalidDNS();
  }
  if (isIPv6(value.split('/')[0])) {
    return { valid: true, message: _('Valid') };
  }

  const cleanedValueWithoutPort = value.replace(/:(\d+)(?=\/|$)/, '');
  const cleanedIpWithoutPath = cleanedValueWithoutPort.split('/')[0];

  if (validateIPV4(cleanedIpWithoutPath).valid) {
    return { valid: true, message: _('Valid') };
  }

  if (validateDomain(cleanedValueWithoutPort).valid) {
    return { valid: true, message: _('Valid') };
  }

  return invalidDNS();
}
