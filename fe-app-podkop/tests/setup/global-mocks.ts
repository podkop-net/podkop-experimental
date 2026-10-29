// tests/setup/global-mocks.ts
globalThis._ = (key: string) => key;

// String.prototype.format of LuCI (luci.js), as far as the page uses it: %s, %d, %%
if (!(String.prototype as unknown as { format?: unknown }).format) {
  Object.defineProperty(String.prototype, 'format', {
    value: function (this: string, ...args: unknown[]) {
      let index = 0;
      return this.replace(/%([%sdh])/g, (_match, kind: string) => {
        if (kind === '%') return '%';
        const value = args[index++];
        return kind === 'd' ? String(Math.trunc(Number(value))) : String(value);
      });
    },
    configurable: true,
    writable: true,
  });
}
