import { describe, expect, it, vi } from 'vitest';

vi.mock('../../../../methods', () => ({ PodkopShellMethods: {} }));
vi.mock('../updateCheckStore', () => ({ updateCheckStore: () => {} }));
// the helpers of the page bring its services, which need a document
vi.mock('../../../../../helpers', () => ({
  insertIf: <T>(condition: boolean, items: T[]) => (condition ? items : []),
}));

const { dnsServerItems } = await import('../runDnsCheck');

describe('dnsServerItems', () => {
  it('keeps the line of one server as before the list', () => {
    expect(
      dnsServerItems([{ type: 'doh', server: '1.1.1.1', status: 1 }], 'order'),
    ).toEqual([{ state: 'success', key: 'Main DNS', value: '1.1.1.1 [doh]' }]);
  });

  it('names the servers of the provider', () => {
    expect(
      dnsServerItems(
        [
          {
            type: 'provider',
            server: '',
            providers: ['192.0.2.53', '192.0.2.54'],
            status: 0,
          },
        ],
        undefined,
      ),
    ).toEqual([
      {
        state: 'error',
        key: 'Main DNS',
        value: "The provider's DNS: 192.0.2.53, 192.0.2.54",
      },
    ]);
    expect(
      dnsServerItems([{ type: 'provider', server: '', status: 0 }], 'order')[0]
        .value,
    ).toBe("The provider's DNS: the router knows none now");
  });

  it('gives each server of a list its line, the first telling how they are asked', () => {
    const servers = [
      { type: 'udp' as const, server: '77.88.8.8', status: 0 as const },
      {
        type: 'provider' as const,
        server: '',
        providers: ['192.0.2.53'],
        status: 1 as const,
      },
    ];
    expect(dnsServerItems(servers, 'fastest')).toEqual([
      {
        state: 'error',
        key: 'DNS 1 of 2, the fastest first',
        value: '77.88.8.8 [udp]',
      },
      {
        state: 'success',
        key: 'DNS 2',
        value: "The provider's DNS: 192.0.2.53",
      },
    ]);
    expect(dnsServerItems(servers, 'order')[0].key).toBe(
      'DNS 1 of 2, in their order',
    );
  });

  it('warns of a server that replies with a refusal', () => {
    expect(
      dnsServerItems(
        [{ type: 'udp', server: '77.88.8.8', status: 0, refusal: 'REFUSED' }],
        'order',
      ),
    ).toEqual([
      {
        state: 'warning',
        key: 'Main DNS',
        value: '77.88.8.8 [udp] — replies REFUSED',
      },
    ]);
  });
});
