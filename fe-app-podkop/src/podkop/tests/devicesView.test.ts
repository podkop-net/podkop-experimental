import { describe, expect, it } from 'vitest';
import { loadView } from './viewHarness';

// The lists of devices of the settings (view/podkop/devices.js): what the field of an interface
// source and the output interface ("out") offer, against LuCI's devices as network.js gives them.

interface FakeNetwork {
  name: string;
  proto: string;
}

// a device of LuCI's network.js: its name, the type LuCI gives it, the networks of netifd that use
// it, the kernel's state (dev: empty when the device is only named in the settings) and its
// addresses
function device(
  name: string,
  type: string,
  networks: FakeNetwork[],
  dev: Record<string, unknown>,
  ipv4: string[] = [],
) {
  return {
    dev,
    getName: () => name,
    getType: () => type,
    getMAC: () => (dev.macaddr as string | undefined) ?? null,
    getNetworks: () =>
      networks.map((network) => ({
        getName: () => network.name,
        getProtocol: () => network.proto,
      })),
    getIPAddrs: () => ipv4,
    getIP6Addrs: () => [],
  };
}

const ETHER = 1;
const ARPHRD_NONE = 65534;
const LOOPBACK = 772;
const PPP = 512;

const DEVICES = [
  // the LAN and the WAN
  device(
    'br-lan',
    'bridge',
    [{ name: 'lan', proto: 'static' }],
    { type: ETHER, macaddr: '02:00:00:00:00:01' },
    ['192.168.1.1/24'],
  ),
  device('lan1', 'ethernet', [], { type: ETHER, macaddr: '02:00:00:00:00:02' }),
  device(
    'eth0',
    'ethernet',
    [{ name: 'wan', proto: 'dhcp' }],
    { type: ETHER, macaddr: '02:00:00:00:00:03' },
    ['100.64.0.2/24'],
  ),
  device('pppoe-wan', 'ethernet', [{ name: 'wan6', proto: 'pppoe' }], {
    type: PPP,
  }),
  device(
    'lo',
    'ethernet',
    [{ name: 'loopback', proto: 'static' }],
    { type: LOOPBACK, macaddr: '00:00:00:00:00:00' },
    ['127.0.0.1/8'],
  ),
  // tunnels netifd knows
  device(
    'wg0',
    'wireguard',
    [{ name: 'vpn', proto: 'wireguard' }],
    { type: ARPHRD_NONE },
    ['10.8.0.2/32'],
  ),
  // the tun of a program, no interface of netifd: a name of the list, and names of their own (a
  // VK TURN client such as CSQTT names its tun as it likes)
  device('tun0', 'ethernet', [], { type: ARPHRD_NONE }, ['10.9.0.2/30']),
  device('csqtt0', 'ethernet', [], { type: ARPHRD_NONE }, ['10.10.0.2/30']),
  device('vkturn', 'ethernet', [], { type: ARPHRD_NONE }),
  // the same kind of tun with an interface of netifd of the protocol "none", in a zone of its own
  device('mytunnel', 'ethernet', [{ name: 'turn', proto: 'none' }], {
    type: ARPHRD_NONE,
  }),
  // a device only named in the settings (a USB modem not plugged in): no state of the kernel
  device('eth9', 'ethernet', [{ name: 'guest', proto: 'static' }], {}),
];

function offered(role: string): string[] {
  const view = loadView('devices.js', {});
  const option: Record<string, unknown> = {};
  view.exports.forRole(option, role);
  option.devices = DEVICES;
  option.wanNetworks = ['wan', 'wan6'];
  const filter = option.filter as (sid: string, name: string) => boolean;
  return DEVICES.map((dev) => dev.getName()).filter((name) =>
    filter.call(option, 'src1', name),
  );
}

describe('the devices an interface source and the output offer', () => {
  it('offers the WAN, the tunnels of netifd and the tun of any program, whatever its name', () => {
    expect(offered('out')).toEqual([
      'eth0',
      'pppoe-wan',
      'wg0',
      'tun0',
      'csqtt0',
      'vkturn',
      'mytunnel',
    ]);
  });

  it('leaves the LAN side out: bridges, ports, the loopback, a device the kernel does not have', () => {
    const out = offered('out');
    for (const name of ['br-lan', 'lan1', 'lo', 'eth9']) {
      expect(out).not.toContain(name);
    }
  });

  it('keeps the LAN list as it was: a device with an IPv4 address that is not of the WAN', () => {
    expect(offered('lan')).toEqual(['br-lan', 'wg0', 'tun0', 'csqtt0']);
  });
});
