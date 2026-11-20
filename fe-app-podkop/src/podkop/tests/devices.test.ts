import { describe, expect, it } from 'vitest';
import {
  deviceItems,
  devicesShadowed,
  hostChoices,
  narrower,
  routedOutside,
  routedWhole,
  ruleDevices,
} from '../devices';

describe('the devices of a rule', () => {
  it('reads a value of several items as many, as the backend does', () => {
    expect(
      deviceItems(['192.168.1.50', ' 192.168.1.60, 192.168.1.61 ']),
    ).toEqual(['192.168.1.50', '192.168.1.60', '192.168.1.61']);
    expect(deviceItems('192.168.1.50 2001:db8::1')).toEqual([
      '192.168.1.50',
      '2001:db8::1',
    ]);
    expect(deviceItems(undefined)).toEqual([]);
  });

  it('keeps the items the backend takes, and tells a field with none of them', () => {
    expect(ruleDevices({ only_devices: ['192.168.1.50', 'word'] })).toEqual({
      limited: true,
      devices: ['192.168.1.50'],
    });
    expect(ruleDevices({ only_devices: ['word', 'fe80::1'] })).toEqual({
      limited: true,
      devices: [],
    });
    expect(ruleDevices({})).toEqual({ limited: false, devices: [] });
  });

  it('routes whole only the devices within them (strict AND)', () => {
    const fully = ['192.168.1.5', '192.168.1.60', '192.168.1.8/30'];
    expect(routedOutside(['192.168.1.0/28'], fully)).toEqual(['192.168.1.60']);
    expect(routedOutside([], fully)).toEqual([]);
    expect(
      routedWhole({
        only_devices: ['192.168.1.0/28'],
        fully_routed_ips: fully,
      }),
    ).toEqual(['192.168.1.5', '192.168.1.8/30']);
    expect(routedWhole({ fully_routed_ips: fully })).toEqual(fully);
    expect(
      routedWhole({ only_devices: ['word'], fully_routed_ips: fully }),
    ).toEqual([]);
  });

  it('names the narrower of two overlapping subnets', () => {
    expect(narrower('192.168.1.0/24', '192.168.1.50')).toBe('192.168.1.50');
    expect(narrower('192.168.1.50', '192.168.1.0/24')).toBe('192.168.1.50');
    expect(narrower('192.168.1.0/24', '192.168.2.0/24')).toBeNull();
  });
});

describe('a rule above a rule of the same list', () => {
  const every = { limited: false, devices: [] };
  const tv = { limited: true, devices: ['192.168.1.50'] };
  const lan = { limited: true, devices: ['192.168.1.0/24'] };
  const pc = { limited: true, devices: ['192.168.1.60'] };
  const none = { limited: true, devices: [] };

  it('takes all of it when it is for every device or for all the devices below', () => {
    expect(devicesShadowed(every, tv)).toBe('all');
    expect(devicesShadowed(every, every)).toBe('all');
    expect(devicesShadowed(lan, tv)).toBe('all');
    expect(devicesShadowed(tv, tv)).toBe('all');
  });

  it('takes some of it when it is for some devices only', () => {
    // the TV above, every device below: the rule of block for the others
    expect(devicesShadowed(tv, every)).toBe('some');
    expect(
      devicesShadowed(tv, { limited: true, devices: ['192.168.1.0/24'] }),
    ).toBe('some');
  });

  it('takes none of it when its devices are others, or it has none', () => {
    expect(devicesShadowed(pc, tv)).toBe('none');
    expect(devicesShadowed(none, every)).toBe('none');
    expect(devicesShadowed(every, none)).toBe('all');
    expect(devicesShadowed(tv, none)).toBe('none');
  });
});

describe('the devices the router knows', () => {
  it('offers their IPv4 addresses by name, in the order of the addresses', () => {
    const hints = {
      hosts: {
        'aa:bb:cc:00:00:02': {
          name: 'tv',
          ipaddrs: ['192.168.1.50'],
          ip6addrs: ['fe80::1', '2001:db8::50'],
        },
        'aa:bb:cc:00:00:01': { ipaddrs: ['192.168.1.9', '192.168.1.50'] },
        'aa:bb:cc:00:00:03': { name: 'old', ipv4: '192.168.1.100' },
        'aa:bb:cc:00:00:04': { name: 'v6', ip6addrs: ['2001:db8::4'] },
      },
    };
    expect(hostChoices(hints)).toEqual([
      ['192.168.1.9', '192.168.1.9 (aa:bb:cc:00:00:01)'],
      ['192.168.1.50', '192.168.1.50 (tv)'],
      ['192.168.1.100', '192.168.1.100 (old)'],
    ]);
    expect(hostChoices(null)).toEqual([]);
    expect(hostChoices({})).toEqual([]);
  });
});
