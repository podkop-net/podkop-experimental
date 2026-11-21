import { subnetContains, validateDevice } from '../validators/validateDevice';
import { validateIPV4 } from '../validators/validateIp';

// The rules only for some devices ("only_devices"): what the page tells of them, by the backend's
// reading of the field (model.Section.Devices).

export interface RuleDevices {
  // the field has items: a rule none of whose items is a device takes nothing
  limited: boolean;
  // the items the backend takes
  devices: string[];
}

// deviceItems are the items of a list option of a rule: a value of several at spaces or commas (a
// file edited by hand) is as many, as the backend reads it.
export function deviceItems(value: unknown): string[] {
  const values = Array.isArray(value) ? value : value == null ? [] : [value];
  return values
    .flatMap((item) => String(item).split(/[\s,]+/))
    .filter((item) => item !== '');
}

// ruleDevices are the devices a rule is only for.
export function ruleDevices(rule?: { only_devices?: unknown }): RuleDevices {
  const items = deviceItems(rule?.only_devices);
  return {
    limited: items.length > 0,
    devices: items.filter((item) => validateDevice(item).valid),
  };
}

// routedOutside are the fully routed IPs that lie within none of the devices: the backend leaves
// them out (strict AND). None when there is no device.
export function routedOutside(
  devices: string[],
  fullyRouted: unknown,
): string[] {
  if (!devices.length) return [];
  return deviceItems(fullyRouted).filter(
    (ip) => !devices.some((device) => subnetContains(device, ip)),
  );
}

// routedWhole are the devices a rule routes whole as the backend takes them: of a rule only for
// some devices, those within its devices, and none when it has no device.
export function routedWhole(rule?: {
  only_devices?: unknown;
  fully_routed_ips?: unknown;
}): string[] {
  const { limited, devices } = ruleDevices(rule);
  return deviceItems(rule?.fully_routed_ips).filter(
    (ip) => !limited || devices.some((device) => subnetContains(device, ip)),
  );
}

// narrower is the narrower of two addresses or subnets when one holds the other, else null.
export function narrower(first: string, second: string): string | null {
  if (subnetContains(first, second)) return second;
  return subnetContains(second, first) ? first : null;
}

// devicesShadowed is how much of the traffic of a lower rule's devices a rule above takes first:
// "all" (it is for every device, or the devices below are all among its own), "none" (it takes no
// device, or none of the devices below), "some".
export function devicesShadowed(
  upper: RuleDevices,
  lower: RuleDevices,
): 'all' | 'some' | 'none' {
  if (!upper.limited) return 'all';
  if (!upper.devices.length) return 'none';
  if (!lower.limited) return 'some';
  if (!lower.devices.length) return 'none';
  const within = (device: string) =>
    upper.devices.some((above) => subnetContains(above, device));
  if (lower.devices.every(within)) return 'all';
  const overlaps = (device: string) =>
    upper.devices.some((above) => narrower(above, device) !== null);
  return lower.devices.some(overlaps) ? 'some' : 'none';
}

// a host of LuCI's host hints (network.getHostHints().hosts, by MAC); ipv4 is the field of LuCI
// before 21.02
interface HostHint {
  name?: string;
  ipaddrs?: string[] | string;
  ip6addrs?: string[];
  ipv4?: string[] | string;
}

// hostChoices are the IPv4 addresses the router knows its devices by (LuCI's host hints: the DHCP
// leases and the neighbours, by MAC), as [address, "address (name)"], each once, in the order of
// the addresses. IPv6 is typed by hand: the hints have link-local and rotating addresses, which a
// rule cannot go by. The hints also hold the router's own addresses, under the MACs of its own
// interfaces (routerMacs): they are left out, since a rule for the router's WAN address takes the
// router's own traffic.
export function hostChoices(
  hints?: {
    hosts?: Record<string, HostHint>;
  } | null,
  routerMacs?: unknown[] | null,
): [string, string][] {
  const hosts = hints?.hosts ?? {};
  const own = new Set(
    (routerMacs ?? []).map((mac) => String(mac ?? '').toUpperCase()),
  );
  const seen = new Set<string>();
  const choices: [string, string][] = [];
  Object.keys(hosts).forEach((mac) => {
    if (own.has(mac.toUpperCase())) return;
    const host = hosts[mac] ?? {};
    deviceItems(host.ipaddrs ?? host.ipv4).forEach((address) => {
      if (!validateIPV4(address).valid || seen.has(address)) return;
      seen.add(address);
      choices.push([address, `${address} (${host.name || mac})`]);
    });
  });
  const key = (address: string) =>
    address.split('.').reduce((sum, octet) => sum * 256 + Number(octet), 0);
  return choices.sort((a, b) => key(a[0]) - key(b[0]));
}
