// A password for a rule's mixed proxy: letters and digits only, so that it needs no
// %-encoding in a proxy address (socks5h://user:password@host:port) and every app can type
// it. 16 of the 62 signs are about 95 bits. A byte of 248 or above is drawn again: 248 is
// 4 × 62, and the bytes below it give each sign as often as any other.
const SIGNS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const FAIR_BELOW = 248;

export function generateProxyPassword(length = 16): string {
  let password = '';
  while (password.length < length) {
    for (const byte of crypto.getRandomValues(new Uint8Array(length))) {
      if (byte < FAIR_BELOW && password.length < length) {
        password += SIGNS[byte % SIGNS.length];
      }
    }
  }
  return password;
}
