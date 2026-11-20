import { ValidationResult } from './types';

// The login of a rule's mixed proxy (mixed_proxy_username, mixed_proxy_password): both parts
// or none. Each part is what every app can type and SOCKS5 carries: printable ASCII without
// the space, at most 255 characters (one byte of length in SOCKS5); HTTP's Basic
// authentication cannot send a colon in the user name. The backend checks the same, and
// leaves the proxy out when the settings have a login it cannot use.

const PRINTABLE = /^[\x21-\x7e]+$/;
const LONGEST = 255;
// a password typed on the page: a short one falls to a LAN device that tries them all
const SHORTEST_PASSWORD = 8;

function ok(): ValidationResult {
  return { valid: true, message: _('Valid') };
}

function validatePart(value: string): ValidationResult {
  if (!PRINTABLE.test(value)) {
    return {
      valid: false,
      message: _('Latin letters, digits and signs only, without spaces'),
    };
  }
  if (value.length > LONGEST) {
    return { valid: false, message: _('At most 255 characters') };
  }
  return ok();
}

export function validateMixedProxyUser(value: string): ValidationResult {
  if (!value) {
    return ok();
  }
  const part = validatePart(value);
  if (!part.valid) {
    return part;
  }
  if (value.includes(':')) {
    return {
      valid: false,
      message: _('No “:” in the user name: HTTP cannot send it'),
    };
  }
  return ok();
}

// The password, and the pair: user is what the user name field has. kept tells that the
// value is the one the settings have already, not typed: the shortest length is not asked
// of it (the backend takes any length).
export function validateMixedProxyPassword(
  value: string,
  user: string,
  kept = false,
): ValidationResult {
  if (!value) {
    return user
      ? {
          valid: false,
          message: _('Set the password too, or clear the user name'),
        }
      : ok();
  }
  if (!user) {
    return {
      valid: false,
      message: _('Set the user name too, or clear the password'),
    };
  }
  const part = validatePart(value);
  if (!part.valid) {
    return part;
  }
  if (!kept && value.length < SHORTEST_PASSWORD) {
    return { valid: false, message: _('At least 8 characters') };
  }
  return ok();
}
