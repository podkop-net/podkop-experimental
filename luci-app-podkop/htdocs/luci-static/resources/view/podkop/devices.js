"use strict";
"require baseclass";
"require firewall";
"require network";
"require tools.widgets as widgets";

// The lists of devices in the settings, by what each field is for. The backend takes every
// name to the device of layer 3 it stands for (the port of a PPPoE connection to
// pppoe-wan, a logical interface of netifd typed by hand to its device), so a list only
// leaves out what can never work in its field. A device chosen before stays shown, so that
// it can be taken off.
//   lan     where the traffic of the LAN comes in: a device with an IPv4 address, not of
//           the WAN (bridges of the LAN and of the guests, a Wi-Fi network without a bridge,
//           a VLAN, a WireGuard server); podkop takes IPv4 only
//   yacd    where YACD is opened from: a device with an address, the WAN's included
//   out     where podkop's own connections go out (the output, a VPN section): the devices
//           of the networks of the WAN and tunnels, whether they have an address now or
//           not (PPPoE that is down, a tunnel not yet up); one without an IPv4 address now
//           is marked so. A tunnel a program makes for itself (a tun of a VK TURN client
//           such as CSQTT, of a VPN client) is there only while it runs, and the list is read
//           again each time the window opens; one that is not up then is typed by name

// protocols of netifd whose interface is a tunnel
const TUNNEL_PROTOCOLS = [
  "wireguard",
  "amneziawg",
  "openvpn",
  "openconnect",
  "vpnc",
  "sstp",
  "l2tp",
  "pptp",
  "gre",
  "gretap",
  "grev6",
  "grev6tap",
  "ipip",
  "ipip6",
  "6in4",
  "6to4",
  "6rd",
  "dslite",
  "vti",
  "vtiv6",
  "xfrm",
  "vxlan",
  "vxlan6",
  "zerotier",
  "tailscale",
];

// a tunnel without an interface of netifd: the tun of OpenVPN or of another program
const TUNNEL_NAME = /^(tun|tap|wg|awg|ovpn|tailscale|zt)/;

// usableIPv4 tells whether an address of LuCI ("192.168.1.1/24") can be the address of
// traffic: not of the loopback, not link-local (a device gives itself 169.254.x.x when
// DHCP does not answer)
function usableIPv4(address) {
  return !/^(127\.|169\.254\.|0\.)/.test(address);
}

function hasIPv4(device) {
  return device.getIPAddrs().some(usableIPv4);
}

function hasAddress(device) {
  return (
    hasIPv4(device) ||
    device.getIP6Addrs().some((address) => !/^(fe80:|::1\/)/i.test(address))
  );
}

function ofWAN(device, wanNetworks) {
  return device
    .getNetworks()
    .some((network) => wanNetworks.includes(network.getName()));
}

// the link type of the kernel of a device that carries IP packets alone, with no link layer:
// the tun of a program, WireGuard (ARPHRD_NONE of linux/if_arp.h)
const ARPHRD_NONE = 65534;

// isLayer3 tells such a device that is there now (LuCI's state of the kernel's devices: a
// device only named in the settings has none). LuCI types the tun of a program "ethernet",
// whatever its name, when no protocol of netifd made it.
function isLayer3(device) {
  return (device.dev || {}).type === ARPHRD_NONE;
}

function isTunnel(device) {
  const networks = device.getNetworks();
  return (
    ["wireguard", "tunnel"].includes(device.getType()) ||
    networks.some((network) =>
      TUNNEL_PROTOCOLS.includes(network.getProtocol()),
    ) ||
    (networks.length === 0 && TUNNEL_NAME.test(device.getName())) ||
    isLayer3(device)
  );
}

const ACCEPTS = {
  lan: (device, wanNetworks) => hasIPv4(device) && !ofWAN(device, wanNetworks),
  yacd: (device) => hasAddress(device),
  out: (device, wanNetworks) => ofWAN(device, wanNetworks) || isTunnel(device),
};

// forRole sets a DeviceSelect up for a field: what it offers, and for "out" the mark of a
// device without an IPv4 address now
function forRole(option, role) {
  option.noaliases = true;
  option.nobridges = false;
  option.noinactive = false;
  option.load = function (section_id) {
    // the devices as they are now, not as the page found them: a tunnel that came up
    // (or was made again under another name) since the page loaded is offered
    const fresh = role === "out" ? network.flushCache() : Promise.resolve();
    return Promise.all([
      firewall.getZones(),
      fresh.then(() =>
        widgets.DeviceSelect.prototype.load.call(this, section_id),
      ),
    ]).then(([zones, value]) => {
      // the networks of the WAN: those of the zones with masquerading
      this.wanNetworks = zones
        .filter((zone) => zone.isMasquerade())
        .flatMap((zone) => zone.getNetworks());
      return value;
    });
  };
  option.filter = function (section_id, value) {
    const device = this.devices.find((dev) => dev.getName() === value);
    return device ? ACCEPTS[role](device, this.wanNetworks || []) : false;
  };
  if (role === "out") {
    option.renderWidget = function (section_id, option_index, cfgvalue) {
      const widget = widgets.DeviceSelect.prototype.renderWidget.call(
        this,
        section_id,
        option_index,
        cfgvalue,
      );
      widget.querySelectorAll("li[data-value]").forEach((item) => {
        const device = this.devices.find(
          (dev) => dev.getName() === item.getAttribute("data-value"),
        );
        if (device && !hasIPv4(device)) {
          item.appendChild(
            E("span", { class: "hide-close" }, [
              " — " + _("no IPv4 address now"),
            ]),
          );
        }
      });
      return widget;
    };
  }
  return option;
}

return baseclass.extend({
  forRole,
});
