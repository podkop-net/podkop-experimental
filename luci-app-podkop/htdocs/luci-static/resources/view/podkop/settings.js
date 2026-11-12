"use strict";
"require form";
"require uci";
"require ui";
"require baseclass";
"require tools.widgets as widgets";
"require network";
"require view.podkop.main as main";
"require view.podkop.devices as devices";

// the public lists of masks of the backend (model.DefaultMaskLists)
const MASK_LISTS = [
  "https://raw.githubusercontent.com/Runnin4ik/dpi-detector/main/whitelist_sni.txt",
  "https://cheburcheck.ru/whitelist/domains.csv",
];

// The provider's DNS servers netifd knows now, for the note under the list: those of the
// interfaces with a default route, as the backend takes them.
function providerDNS() {
  return network
    .getWANNetworks()
    .then((networks) => {
      const servers = [];
      networks.forEach((wan) => {
        (wan.getDNSAddrs() || []).forEach((server) => {
          if (!servers.includes(server)) servers.push(server);
        });
      });
      return servers;
    })
    .catch(() => []);
}

// A field of the DNS table keeps its value in a row the page has not drawn yet: LuCI removes
// the value of a field it cannot see when it parses the form (a hidden one, as the address of
// the provider's row, is still removed), and a row Add has just made is not drawn when the
// save that stages it parses the form.
function keepUndrawn(column) {
  column.remove = function (section_id) {
    const root = this.map.root;
    if (root && !root.querySelector('[data-sid="' + section_id + '"]')) {
      return;
    }
    return form.AbstractValue.prototype.remove.apply(this, arguments);
  };
}

// The DNS servers in their order, a row each, dragged by the handle to another place, as the
// rows of a rule are. A file without the list has the one server of its options as the first row:
// it is made in the page and written with the next save, so opening the page changes nothing.
function dnsServersTable(section) {
  const o = section.option(
    form.SectionValue,
    "_dns_servers",
    form.TableSection,
    "dns_server",
    _("DNS servers"),
    _(
      "Asked in the order of the list or the fastest first, as chosen below. Drag a row by its handle to move it.",
    ),
  );
  const table = o.subsection;
  table.anonymous = true;
  table.addremove = true;
  table.sortable = true;
  table.nodescriptions = true;
  table.load = function () {
    if (!uci.sections("podkop", "dns_server").length) {
      const row = uci.add("podkop", "dns_server");
      uci.set(
        "podkop",
        row,
        "type",
        uci.get("podkop", "settings", "dns_type") || "doh",
      );
      uci.set(
        "podkop",
        row,
        "server",
        uci.get("podkop", "settings", "dns_server") || "1.1.1.1",
      );
    }
    return Promise.all([
      form.TableSection.prototype.load.apply(this, arguments),
      providerDNS().then((servers) => {
        table.description =
          _(
            "Asked in the order of the list or the fastest first, as chosen below. Drag a row by its handle to move it.",
          ) +
          " " +
          (servers.length
            ? _("The provider's DNS now: %s.").format(servers.join(", "))
            : _("The router knows no DNS server of the provider now."));
      }),
    ]);
  };
  // the order is the order the servers are asked in: dragging only
  table.handleSort = function () {};
  // A new row is a server at once. LuCI stages the section of a new row before its fields
  // are filled in; left so and applied later from the pending changes (another page's Save &
  // Apply), an empty row was a list the backend refused. The save that stages it parses the
  // form, where the row is not drawn yet: its fields keep what Add gave them (keepUndrawn).
  table.handleAdd = function (ev, name) {
    const config = this.uciconfig || this.map.config;
    const row = this.map.data.add(config, this.sectiontype, name);
    this.map.data.set(config, row, "type", "doh");
    this.map.data.set(
      config,
      row,
      "server",
      Object.keys(main.DNS_SERVER_OPTIONS)[0] || "1.1.1.1",
    );
    return this.map.save(null, true);
  };
  // one server is left at least: without the list the server of the options would come back
  table.handleRemove = function () {
    if (this.cfgsections().length > 1) {
      return form.TableSection.prototype.handleRemove.apply(this, arguments);
    }
    ui.addTimeLimitedNotification(
      null,
      E("p", {}, [
        _(
          "One DNS server is needed at least: change this one, or add another first.",
        ),
      ]),
      5000,
      "warning",
    );
    return Promise.resolve();
  };
  table.renderSectionPlaceholder = function () {
    return E("em", {}, [_("No DNS server: add one.")]);
  };

  let column = table.option(form.ListValue, "type", _("Type"));
  column.value("doh", _("DNS over HTTPS (DoH)"));
  column.value("dot", _("DNS over TLS (DoT)"));
  column.value("udp", _("UDP (Unprotected DNS)"));
  column.value("provider", _("The provider's DNS"));
  column.default = "doh";
  column.rmempty = false;
  keepUndrawn(column);

  column = table.option(form.Value, "server", _("Address"));
  Object.entries(main.DNS_SERVER_OPTIONS).forEach(([key, label]) => {
    column.value(key, _(label));
  });
  // the provider's row has no address of its own
  ["doh", "dot", "udp"].forEach((type) => column.depends("type", type));
  column.rmempty = false;
  keepUndrawn(column);
  column.validate = function (section_id, value) {
    const validation = main.validateDNS(value);

    if (validation.valid) {
      return true;
    }

    return validation.message;
  };
}

function createSettingsContent(section, singBoxFeatures = []) {
  dnsServersTable(section);

  let o = section.option(
    form.ListValue,
    "dns_mode",
    _("How the DNS servers are asked"),
    _(
      "In their order: a server is asked only when the ones above it do not answer. The fastest first: the server that answered fastest lately is asked, the next fastest when it does not answer.",
    ),
  );
  o.value("order", _("In their order"));
  o.value("fastest", _("The fastest first"));
  o.default = "order";
  o.rmempty = false;

  o = section.option(
    form.Value,
    "bootstrap_dns_server",
    _("Bootstrap DNS server"),
    _(
      "The DNS server used to look up the IP address of an upstream DNS server",
    ),
  );
  Object.entries(main.BOOTSTRAP_DNS_SERVER_OPTIONS).forEach(([key, label]) => {
    o.value(key, _(label));
  });
  o.default = "77.88.8.8";
  o.rmempty = false;
  o.validate = function (section_id, value) {
    const validation = main.validateDNS(value);

    if (validation.valid) {
      return true;
    }

    return validation.message;
  };

  o = section.option(
    form.Value,
    "dns_rewrite_ttl",
    _("DNS Rewrite TTL"),
    _("Time in seconds for DNS record caching (default: 60)"),
  );
  o.default = "60";
  o.rmempty = false;
  o.validate = function (section_id, value) {
    if (!value) {
      return _("TTL value cannot be empty");
    }

    const ttl = parseInt(value);
    if (isNaN(ttl) || ttl < 0) {
      return _("TTL must be a positive number");
    }

    return true;
  };

  o = section.option(
    widgets.DeviceSelect,
    "source_network_interfaces",
    _("Source Network Interface"),
    _("Select the network interface from which the traffic will originate"),
  );
  o.default = "br-lan";
  o.multiple = true;
  devices.forRole(o, "lan");

  o = section.option(
    form.Flag,
    "enable_output_network_interface",
    _("Enable Output Network Interface"),
    _(
      "Without it, podkop's own connections go where the routing of the router sends them (mwan3 included)",
    ),
  );
  o.default = "0";
  o.rmempty = false;

  o = section.option(
    widgets.DeviceSelect,
    "output_network_interface",
    _("Output Network Interface"),
    _(
      "Every connection of podkop goes out through this WAN or tunnel, whatever the routing of the router says",
    ),
  );
  o.multiple = false;
  o.depends("enable_output_network_interface", "1");
  devices.forRole(o, "out");

  o = section.option(
    form.Flag,
    "enable_yacd",
    _("Enable YACD"),
    _(
      "The web panel of sing-box, opened from the devices chosen below; without it the panel's API is reached from the router only",
    ),
  );
  o.default = "0";
  o.rmempty = false;

  // The API of YACD listens on every address, and the firewall of the backend lets in only
  // these devices (and the router itself): no device by default, the choice is the user's
  o = section.option(
    widgets.DeviceSelect,
    "yacd_interfaces",
    _("YACD Network Interfaces"),
    _(
      "The devices YACD is opened from. A device of the WAN also needs its port 9090 opened in the firewall of the router",
    ),
  );
  o.depends("enable_yacd", "1");
  o.multiple = true;
  o.optional = false;
  o.rmempty = false;
  // only the devices with an address of their own: the firewall lets in the device a
  // connection comes in through, which is the one with the address (a bridge, not its
  // ports)
  devices.forRole(o, "yacd");
  o.validate = function (section_id) {
    return L.toArray(this.formvalue(section_id)).length
      ? true
      : _("Choose the devices YACD is opened from");
  };

  o = section.option(
    form.Value,
    "yacd_secret_key",
    _("YACD Secret Key"),
    _("The key YACD asks for; the links below carry it"),
  );
  o.depends("enable_yacd", "1");
  o.rmempty = false;
  // the backend keeps a key in it with YACD off too, and makes one when there is none:
  // hidden, the option must not be deleted by a save
  o.retain = true;

  // The links that open YACD logged in: an address of each device of YACD, from the
  // settings as they were saved
  o = section.option(form.DummyValue, "_yacd_links", _("YACD Links"));
  o.depends("enable_yacd", "1");
  o.load = function (section_id) {
    const enabled = uci.get("podkop", section_id, "enable_yacd") === "1";
    const secret = uci.get("podkop", section_id, "yacd_secret_key") || "";
    let names = L.toArray(uci.get("podkop", section_id, "yacd_interfaces"));
    if (!names.length) {
      names = L.toArray(
        uci.get("podkop", section_id, "source_network_interfaces"),
      );
    }
    if (!names.length) {
      names = ["br-lan"];
    }
    // a name of a network of netifd stands for its device of layer 3, as in the backend
    return Promise.all([network.getDevices(), network.getNetworks()]).then(
      ([all, networks]) => {
        const addresses = names.flatMap((name) => {
          const net = networks.find(
            (candidate) => candidate.getName() === name.replace(/^@/, ""),
          );
          const device =
            (net && net.getL3Device()) ||
            all.find((candidate) => candidate.getName() === name);
          return device ? device.getIPAddrs() : [];
        });
        this.links =
          enabled && secret ? main.getYacdLinks(addresses, secret) : [];
      },
    );
  };
  o.renderWidget = function () {
    if (!this.links.length) {
      return E("em", {}, [_("The links appear here after Save & Apply")]);
    }
    return E(
      "div",
      {},
      this.links.map((link) =>
        E("div", {}, [
          E("a", { href: link, target: "_blank", rel: "noopener" }, [link]),
        ]),
      ),
    );
  };

  if (singBoxFeatures.includes("tls.utls-fallback")) {
    // the default writes nothing: the backend takes no option as enabled
    o = section.option(
      form.ListValue,
      "utls_fallback",
      _("uTLS-fallback"),
      _(
        "Before a connection with the uTLS fingerprint of a link, that fingerprint without the X25519MLKEM768 key share is tried, then firefox; the first one the server and the network take is kept and checked again once a day. Disabled: the fingerprint of the link is sent as it is",
      ),
    );
    o.value("", _("Default (enabled)"));
    o.value("enabled", _("Enabled"));
    o.value("disabled", _("Disabled"));
    o.rmempty = true;
  }

  o = section.option(
    form.Flag,
    "disable_quic",
    _("Disable QUIC"),
    _(
      "Disable the QUIC protocol to improve compatibility or fix issues with video streaming",
    ),
  );
  o.default = "0";
  o.rmempty = false;

  // "Find a mask" on the dashboard tries its built-in names and, in turn with them, the names of a
  // public whitelists; the backend downloads them for each search and keeps the last copies in RAM
  o = section.option(
    form.Flag,
    "mask_list",
    _("Public lists of masks"),
    _(
      "“Find a mask” on the dashboard also tries the names of public whitelists, downloaded for each search directly or through your servers. Off: only the built-in names",
    ),
  );
  o.default = "1";
  o.rmempty = false;

  // the defaults are those of the backend (model.DefaultMaskLists): an empty list is them
  o = section.option(
    form.DynamicList,
    "mask_list_url",
    _("Addresses of the lists of masks"),
    _(
      "One host name per line in each list; their names are tried in turn with the built-in ones. Empty: the lists of Runnin4ik/dpi-detector and cheburcheck.ru",
    ),
  );
  o.default = MASK_LISTS;
  o.placeholder = "https://example.com/whitelist.txt";
  o.rmempty = true;
  o.depends("mask_list", "1");
  o.validate = function (section_id, value) {
    if (!value || value.length === 0) {
      return true;
    }

    const validation = main.validateUrl(value);

    if (validation.valid) {
      return true;
    }

    return validation.message;
  };

  // The check of the servers: one for the servers of every rule (urltest of sing-box). The
  // rounds take the URLs in turn; the delay of a server is the median of a cycle of them.
  o = section.option(
    form.DynamicList,
    "urltest_testing_url",
    _("Server check URLs"),
    _(
      "One check for the servers of every rule. Each round tests every server with the next URL of the list; the delay of a server is the median of a full cycle, so one slow URL or one stray test does not change the server in use. A server is unavailable when two URLs do not answer through it. URLs of different companies are best",
    ),
  );
  o.value(
    "https://www.gstatic.com/generate_204",
    "https://www.gstatic.com/generate_204 (Google)",
  );
  o.value(
    "https://cp.cloudflare.com/generate_204",
    "https://cp.cloudflare.com/generate_204 (Cloudflare)",
  );
  o.value(
    "https://captive.apple.com/hotspot-detect.html",
    "https://captive.apple.com/hotspot-detect.html (Apple)",
  );
  o.value(
    "https://detectportal.firefox.com/success.txt",
    "https://detectportal.firefox.com/success.txt (Fastly)",
  );
  o.value(
    "https://www.apple.com/library/test/success.html",
    "https://www.apple.com/library/test/success.html (Akamai)",
  );
  o.default = [
    "https://www.gstatic.com/generate_204",
    "https://cp.cloudflare.com/generate_204",
    "https://captive.apple.com/hotspot-detect.html",
    "https://detectportal.firefox.com/success.txt",
    "https://www.apple.com/library/test/success.html",
  ];
  o.rmempty = false;
  o.validate = function (section_id, value) {
    if (!value || value.length === 0) {
      return true;
    }

    const validation = main.validateUrl(value);

    if (validation.valid) {
      return true;
    }

    return validation.message;
  };

  o = section.option(
    form.ListValue,
    "urltest_check_interval",
    _("Server check interval"),
    _("The interval between connectivity tests"),
  );
  o.renderWidget = function (section_id, option_index, cfgvalue) {
    this.keylist = [];
    this.vallist = [];
    this.value("30s", _("Every 30 seconds"));
    this.value("1m", _("Every 1 minute"));
    this.value("3m", _("Every 3 minutes"));
    this.value("5m", _("Every 5 minutes"));
    // an interval set by hand stays shown
    if (cfgvalue && !this.keylist.includes(cfgvalue)) {
      this.value(cfgvalue, cfgvalue);
    }
    return form.ListValue.prototype.renderWidget.call(
      this,
      section_id,
      option_index,
      cfgvalue,
    );
  };
  o.default = "1m";
  o.rmempty = false;

  o = section.option(
    form.Value,
    "urltest_tolerance",
    _("Server check tolerance, ms"),
    _("The server in use changes only for one faster by this much"),
  );
  o.default = "50";
  o.rmempty = false;
  o.validate = function (section_id, value) {
    if (!value || value.length === 0) {
      return true;
    }

    const parsed = parseFloat(value);

    if (
      /^[0-9]+$/.test(value) &&
      !isNaN(parsed) &&
      isFinite(parsed) &&
      parsed >= 50 &&
      parsed <= 1000
    ) {
      return true;
    }

    return _("Must be a number in the range of 50 - 1000");
  };

  if (singBoxFeatures.includes("urltest.download_url")) {
    o = section.option(
      form.ListValue,
      "urltest_download_check",
      _("Download Check"),
      _(
        "Before switching to a server, 64 KiB is downloaded through it, so a server that freezes connections after about 16 KB is skipped",
      ),
    );
    o.value("default", _("Default"));
    o.value("off", _("Disabled"));
    o.value("custom", _("Custom URL"));
    o.default = "default";

    o = section.option(
      form.Value,
      "urltest_download_url",
      _("Download Check URL"),
      _("The URL must serve at least 64 KiB or announce a shorter length"),
    );
    Object.entries(main.URLTEST_DOWNLOAD_URL_OPTIONS).forEach(
      ([key, label]) => {
        o.value(key, _(label));
      },
    );
    o.default = "https://speed.cloudflare.com/__down?bytes=65536";
    o.rmempty = false;
    o.depends("urltest_download_check", "custom");

    o.validate = function (section_id, value) {
      if (!value || value.length === 0) {
        return true;
      }

      const validation = main.validateUrl(value);

      if (validation.valid) {
        return true;
      }

      return validation.message;
    };
  }

  o = section.option(
    form.ListValue,
    "update_interval",
    _("List Update Frequency"),
    _(
      "Select how often the domain or subnet lists are updated automatically. A list is downloaded directly; one that does not come directly comes through the servers of your first rules",
    ),
  );
  Object.entries(main.UPDATE_INTERVAL_OPTIONS).forEach(([key, label]) => {
    o.value(key, _(label));
  });
  o.default = "1d";
  o.rmempty = false;

  o = section.option(
    form.Flag,
    "dont_touch_dhcp",
    _("Dont Touch My DHCP!"),
    _("Podkop will not modify your DHCP configuration"),
  );
  o.default = "0";
  o.rmempty = false;

  o = section.option(
    form.Value,
    "cache_path",
    _("Cache File Path"),
    _(
      "Select or enter path for the cache file: FakeIP addresses and downloaded lists. Change this ONLY if you know what you are doing",
    ),
  );
  o.value("/var/run/podkop/cache.db", "RAM (/var/run/podkop/cache.db)");
  o.value("/usr/share/podkop/cache.db", "Flash (/usr/share/podkop/cache.db)");
  o.default = "/usr/share/podkop/cache.db";
  o.rmempty = false;
  o.validate = function (section_id, value) {
    if (!value) {
      return _("Cache file path cannot be empty");
    }

    if (!value.startsWith("/")) {
      return _("Path must be absolute (start with /)");
    }

    if (!value.endsWith("cache.db")) {
      return _("Path must end with cache.db");
    }

    const parts = value.split("/").filter(Boolean);
    if (parts.length < 2) {
      return _("Path must contain at least one directory (like /tmp/cache.db)");
    }

    return true;
  };

  o = section.option(
    form.ListValue,
    "log_level",
    _("Log Level"),
    _("Select the log level for sing-box"),
  );
  o.value("trace", "Trace");
  o.value("debug", "Debug");
  o.value("info", "Info");
  o.value("warn", "Warn");
  o.value("error", "Error");
  o.value("fatal", "Fatal");
  o.value("panic", "Panic");
  o.default = "warn";
  o.rmempty = false;

  o = section.option(
    form.Flag,
    "exclude_ntp",
    _("Exclude NTP"),
    _(
      "Exclude NTP protocol traffic from the tunnel to prevent it from being routed through the proxy or VPN",
    ),
  );
  o.default = "0";
  o.rmempty = false;

  o = section.option(
    form.DynamicList,
    "routing_excluded_ips",
    _("Routing Excluded IPs"),
    _("Specify a local IP address to be excluded from routing"),
  );
  o.placeholder = "IP";
  o.rmempty = true;
  o.validate = function (section_id, value) {
    // Optional
    if (!value || value.length === 0) {
      return true;
    }

    const validation = main.validateIPV4(value);

    if (validation.valid) {
      return true;
    }

    return validation.message;
  };
}

const EntryPoint = {
  createSettingsContent,
};

return baseclass.extend(EntryPoint);
