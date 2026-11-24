// tests/setup/global-mocks.ts
globalThis._ = (key: string) => key;

// String.prototype.format of LuCI (luci.js), as far as the page uses it: %s, %d, %%, and
// %1024.2m of an amount of bytes ("1.50 Ki", with the B of the text after it)
function binaryUnits(value: unknown): string {
  const units = ['', 'Ki', 'Mi', 'Gi', 'Ti', 'Pi', 'Ei'];
  let amount = Number(value) || 0;
  let unit = 0;
  for (; unit < units.length - 1 && amount > 1024; unit++) amount /= 1024;
  return (unit ? amount.toFixed(2) : String(amount)) + ' ' + units[unit];
}

if (!(String.prototype as unknown as { format?: unknown }).format) {
  Object.defineProperty(String.prototype, 'format', {
    value: function (this: string, ...args: unknown[]) {
      let index = 0;
      return this.replace(/%(1024\.2m|[%sdh])/g, (_match, kind: string) => {
        if (kind === '%') return '%';
        const value = args[index++];
        if (kind === '1024.2m') return binaryUnits(value);
        return kind === 'd' ? String(Math.trunc(Number(value))) : String(value);
      });
    },
    configurable: true,
    writable: true,
  });
}
