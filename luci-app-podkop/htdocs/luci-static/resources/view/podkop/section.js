"use strict";
"require form";
"require baseclass";
"require ui";
"require uci";
"require tools.widgets as widgets";
"require view.podkop.main as main";
"require view.podkop.devices as devices";

// The value an option of a section has in the form now: what is being edited, else what is
// saved. An option that is not shown has no value in the form.
function currentValue(section, section_id, option) {
  const value = section.formvalue(section_id, option);
  return value != null ? value : uci.get("podkop", section_id, option);
}

// The sections a connection goes through from a section on, in order, while each is a proxy
// section with a detour; it stops at a section met before.
function detourChain(section, from) {
  const chain = [];
  let next = from;
  while (next && !chain.includes(next)) {
    chain.push(next);
    // a VPN section ends the way: it connects through nothing (no loop at it)
    if (currentValue(section, next, "connection_type") !== "proxy") {
      return { chain, loopsAt: null };
    }
    next = currentValue(section, next, "detour");
  }
  return { chain, loopsAt: next && chain.includes(next) ? next : null };
}

const PROXY_CONFIG_LABELS = {
  url: "Connection URL",
  selector: "Selector",
  urltest: "URLTest",
  outbound: "Outbound Config",
};

// The sections a section can connect through: proxy and VPN sections other than itself whose
// own way does not lead back to it, each named with what it is.
function detourCandidates(section, section_id) {
  return uci
    .sections("podkop", "section")
    .map((item) => item[".name"])
    .filter((name) => name !== section_id)
    .filter((name) => {
      const type = currentValue(section, name, "connection_type");
      return (
        (type === "proxy" || type === "vpn") &&
        !detourChain(section, name).chain.includes(section_id)
      );
    })
    .map((name) => {
      const type = currentValue(section, name, "connection_type");
      const what =
        type === "vpn"
          ? "VPN, " + (currentValue(section, name, "interface") || "?")
          : _("Proxy") +
            ", " +
            _(
              PROXY_CONFIG_LABELS[
                currentValue(section, name, "proxy_config_type") || "url"
              ] || "Connection URL",
            );
      return { name, label: name + " — " + what };
    });
}

// The lists of "Connect through" of the sections follow a change of one of them: a section
// whose way leads back is no longer offered. A choice that is no longer offered stays, marked,
// and validate tells why.
function refreshDetourLists(section) {
  const prefix = "widget.cbid.podkop.";
  document
    .querySelectorAll('select[id^="' + prefix + '"][id$=".detour"]')
    .forEach((select) => {
      const section_id = select.id.slice(prefix.length, -".detour".length);
      const chosen = select.value;
      const offered = [
        { name: "", label: _("Directly") },
        ...detourCandidates(section, section_id),
      ];
      if (chosen && !offered.some((item) => item.name === chosen)) {
        offered.push({
          name: chosen,
          label: chosen + " (" + _("not available") + ")",
        });
      }
      select.replaceChildren(
        ...offered.map(({ name, label }) =>
          E("option", { value: name }, [label]),
        ),
      );
      select.value = chosen;
    });
}

// The way of the traffic of a section that connects through another one, as a line.
function detourPath(section, section_id, detour) {
  if (!detour) {
    return _("Path") + ": " + [_("router"), section_id, _("site")].join(" → ");
  }
  const { chain } = detourChain(section, detour);
  return (
    _("Path") +
    ": " +
    [_("router"), ...chain.reverse(), section_id, _("site")].join(" → ")
  );
}

function createSectionContent(section, singBoxFeatures = []) {
  let o = section.option(
    form.ListValue,
    "connection_type",
    _("Connection Type"),
    _("Select between VPN and Proxy connection methods for traffic routing"),
  );
  o.value("proxy", "Proxy");
  o.value("vpn", "VPN");
  o.value("group", _("Group"));
  o.value("block", "Block");
  o.value("exclusion", "Exclusion");

  // the group of servers of subscriptions the traffic goes through (tab Groups)
  o = section.option(
    form.ListValue,
    "group",
    _("Group"),
    _(
      "The group of servers of subscriptions the traffic of this section goes through: the fastest of them, or the one chosen on the dashboard",
    ),
  );
  o.depends("connection_type", "group");
  o.rmempty = false;
  // LuCI would refuse an empty choice as "Expecting: non-empty value": validate tells why
  o.optional = true;
  o.load = function (section_id) {
    this.keylist = [];
    this.vallist = [];
    uci.sections("podkop", "group").forEach((item) => {
      this.value(item[".name"], item[".name"]);
    });
    // a list of LuCI with no choice is not drawn at all: the section would not show
    if (!this.keylist.length) {
      this.value("", _("No group yet: make one on the tab Groups"));
    }
    const value = uci.get("podkop", section_id, "group");
    // a group that is no longer there stays shown, and validate tells why
    if (value && !this.keylist.includes(value)) {
      this.value(value, value + " (" + _("deleted") + ")");
    }
    return form.ListValue.prototype.load.call(this, section_id);
  };
  o.validate = function (section_id, value) {
    if (!value) {
      return _("Choose a group: groups are made on the tab Groups");
    }
    if (!uci.get("podkop", value) || uci.get("podkop", value)[".type"] !== "group") {
      return _("There is no group %s: choose another one").format(value);
    }
    return true;
  };

  o = section.option(
    form.ListValue,
    "proxy_config_type",
    _("Configuration Type"),
    _("Select how to configure the proxy"),
  );
  o.value("url", _("Connection URL"));
  o.value("selector", _("Selector"));
  o.value("urltest", _("URLTest"));
  o.value("outbound", _("Outbound Config"));
  o.default = "url";
  o.depends("connection_type", "proxy");

  o = section.option(
    form.TextValue,
    "proxy_string",
    _("Proxy Configuration URL"),
    _(
      "Share links: vless, ss, trojan, socks, http(s), hysteria2, tuic, and vmess, anytls, hysteria, naive where the engine has them",
    ),
  );
  o.depends("proxy_config_type", "url");
  o.rows = 5;
  // Enable soft wrapping for multi-line proxy URLs (e.g., for URLTest proxy links)
  o.wrap = "soft";
  // Render as a textarea to allow multiple proxy URLs/configs
  o.textarea = true;
  o.rmempty = false;
  o.sectionDescriptions = new Map();
  o.validate = function (section_id, value) {
    // Optional
    if (!value || value.length === 0) {
      return true;
    }

    const validation = main.validateProxyUrl(value);

    if (validation.valid) {
      return true;
    }

    return validation.message;
  };

  o = section.option(
    form.TextValue,
    "outbound_json",
    _("Outbound Configuration"),
    _("Enter complete outbound configuration in JSON format"),
  );
  o.depends("proxy_config_type", "outbound");
  o.rows = 10;
  o.validate = function (section_id, value) {
    // Optional
    if (!value || value.length === 0) {
      return true;
    }

    const validation = main.validateOutboundJson(value);

    if (validation.valid) {
      return true;
    }

    return validation.message;
  };

  o = section.option(
    form.DynamicList,
    "selector_proxy_links",
    _("Selector Proxy Links"),
    _(
      "Share links: vless, ss, trojan, socks, http(s), hysteria2, tuic, and vmess, anytls, hysteria, naive where the engine has them",
    ),
  );
  o.depends("proxy_config_type", "selector");
  o.rmempty = false;
  o.validate = function (section_id, value) {
    // Optional
    if (!value || value.length === 0) {
      return true;
    }

    const validation = main.validateProxyUrl(value);

    if (validation.valid) {
      return true;
    }

    return validation.message;
  };

  o = section.option(
    form.DynamicList,
    "urltest_proxy_links",
    _("URLTest Proxy Links"),
    _(
      "Share links: vless, ss, trojan, socks, http(s), hysteria2, tuic, and vmess, anytls, hysteria, naive where the engine has them",
    ),
  );
  o.depends("proxy_config_type", "urltest");
  o.rmempty = false;
  o.validate = function (section_id, value) {
    // Optional
    if (!value || value.length === 0) {
      return true;
    }

    const validation = main.validateProxyUrl(value);

    if (validation.valid) {
      return true;
    }

    return validation.message;
  };

  if (singBoxFeatures.includes("urltest.fallbacks")) {
    o = section.option(
      form.DynamicList,
      "urltest_fallback_links",
      _("Fallback URLs"),
      _(
        "Used in this order only while none of the URLTest proxy links responds",
      ),
    );
    o.depends("proxy_config_type", "urltest");
    o.validate = function (section_id, value) {
      // Optional
      if (!value || value.length === 0) {
        return true;
      }

      const validation = main.validateProxyUrl(value);

      if (validation.valid) {
        return true;
      }

      return validation.message;
    };
  }

  o = section.option(
    form.ListValue,
    "urltest_check_interval",
    _("URLTest Check Interval"),
    _("The interval between connectivity tests"),
  );
  o.value("30s", _("Every 30 seconds"));
  o.value("1m", _("Every 1 minute"));
  o.value("3m", _("Every 3 minutes"));
  o.value("5m", _("Every 5 minutes"));
  o.default = "3m";
  o.depends("proxy_config_type", "urltest");

  o = section.option(
    form.Value,
    "urltest_tolerance",
    _("URLTest Tolerance"),
    _(
      "The maximum difference in response times (ms) allowed when comparing servers",
    ),
  );
  o.default = "50";
  o.rmempty = false;
  o.depends("proxy_config_type", "urltest");
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

  o = section.option(
    form.Value,
    "urltest_testing_url",
    _("URLTest Testing URL"),
    _("The URL used to test server connectivity"),
  );
  o.value(
    "https://www.gstatic.com/generate_204",
    "https://www.gstatic.com/generate_204 (Google)",
  );
  o.value(
    "https://cp.cloudflare.com/generate_204",
    "https://cp.cloudflare.com/generate_204 (Cloudflare)",
  );
  o.value("https://captive.apple.com", "https://captive.apple.com (Apple)");
  o.value(
    "https://connectivity-check.ubuntu.com",
    "https://connectivity-check.ubuntu.com (Ubuntu)",
  );
  o.default = "https://www.gstatic.com/generate_204";
  o.rmempty = false;
  o.depends("proxy_config_type", "urltest");

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
    o.depends("proxy_config_type", "urltest");

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
    o.depends({
      proxy_config_type: "urltest",
      urltest_download_check: "custom",
    });

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
    form.Flag,
    "enable_udp_over_tcp",
    _("UDP over TCP"),
    _("Applicable for SOCKS and Shadowsocks proxy"),
  );
  o.default = "0";
  o.depends("connection_type", "proxy");
  o.rmempty = false;

  // the section the connections to the servers of this one go through (detour of sing-box):
  // offered from the sections of the form as they are now, a loop left out
  o = section.option(
    form.ListValue,
    "detour",
    _("Connect through"),
    _(
      "The connection to the server of this section goes through the chosen section: the server sees the address of the server of that section, not the one of the router",
    ),
  );
  o.depends("connection_type", "proxy");
  o.renderWidget = function (section_id, option_index, cfgvalue) {
    this.keylist = [];
    this.vallist = [];
    this.value("", _("Directly"));
    detourCandidates(this.section, section_id).forEach(({ name, label }) =>
      this.value(name, label),
    );
    // a saved choice that is no longer offered stays shown, and validate tells why
    if (cfgvalue && !this.keylist.includes(cfgvalue)) {
      this.value(cfgvalue, cfgvalue + " (" + _("not available") + ")");
    }
    const widget = form.ListValue.prototype.renderWidget.call(
      this,
      section_id,
      option_index,
      cfgvalue,
    );
    return E("div", {}, [
      widget,
      E(
        "div",
        { class: "cbi-value-description", id: "pdk-detour-path-" + section_id },
        // a text node: the names of the sections are no HTML
        [detourPath(this.section, section_id, cfgvalue)],
      ),
    ]);
  };
  o.onchange = function (ev, section_id, value) {
    const path = document.getElementById("pdk-detour-path-" + section_id);
    if (path) {
      path.textContent = detourPath(this.section, section_id, value);
    }
    refreshDetourLists(this.section);
  };
  o.validate = function (section_id, value) {
    if (!value) {
      return true;
    }
    const type = currentValue(this.section, value, "connection_type");
    if (type !== "proxy" && type !== "vpn") {
      return _("Section %s is not a proxy or VPN section").format(value);
    }
    const { chain, loopsAt } = detourChain(this.section, value);
    // back to this section, or round among the sections it leads to
    if (chain.includes(section_id)) {
      return _("A loop: %s").format(
        [section_id, ...chain.slice(0, chain.indexOf(section_id) + 1)].join(
          " → ",
        ),
      );
    }
    if (loopsAt) {
      return _("A loop: %s").format(
        [...chain.slice(chain.indexOf(loopsAt)), loopsAt].join(" → "),
      );
    }
    return true;
  };

  // a tunnel, or a WAN: a section of a WAN with its mixed proxy sends what is given
  // to it around the tunnels (the torrent client of the FAQ of podkop)
  o = section.option(
    widgets.DeviceSelect,
    "interface",
    _("Network Interface"),
    _("The tunnel, or the WAN, the traffic of this section goes out through"),
  );
  o.depends("connection_type", "vpn");
  devices.forRole(o, "out");

  o = section.option(
    form.Flag,
    "domain_resolver_enabled",
    _("Domain Resolver"),
    _("Enable built-in DNS resolver for domains handled by this section"),
  );
  o.default = "0";
  o.rmempty = false;
  o.depends("connection_type", "vpn");

  o = section.option(
    form.ListValue,
    "domain_resolver_dns_type",
    _("DNS Protocol Type"),
    _("Select the DNS protocol type for the domain resolver"),
  );
  o.value("doh", _("DNS over HTTPS (DoH)"));
  o.value("dot", _("DNS over TLS (DoT)"));
  o.value("udp", _("UDP (Unprotected DNS)"));
  o.default = "udp";
  o.rmempty = false;
  o.depends("domain_resolver_enabled", "1");

  o = section.option(
    form.Value,
    "domain_resolver_dns_server",
    _("DNS Server"),
    _("Select or enter DNS server address"),
  );
  Object.entries(main.DNS_SERVER_OPTIONS).forEach(([key, label]) => {
    o.value(key, _(label));
  });
  o.default = "8.8.8.8";
  o.rmempty = false;
  o.depends("domain_resolver_enabled", "1");
  o.validate = function (section_id, value) {
    const validation = main.validateDNS(value);

    if (validation.valid) {
      return true;
    }

    return validation.message;
  };

  o = section.option(
    form.DynamicList,
    "community_lists",
    _("Community Lists"),
    _("Select a predefined list for routing") +
      ' <a href="https://github.com/itdoginfo/allow-domains" target="_blank">github.com/itdoginfo/allow-domains</a>',
  );
  o.placeholder = "Service list";
  Object.entries(main.DOMAIN_LIST_OPTIONS).forEach(([key, label]) => {
    o.value(key, _(label));
  });
  o.rmempty = true;
  let lastValues = [];
  let isProcessing = false;

  o.onchange = function (ev, section_id, value) {
    if (isProcessing) return;
    isProcessing = true;

    try {
      const values = Array.isArray(value) ? value : [value];
      let newValues = [...values];
      let notifications = [];

      const selectedRegionalOptions = main.REGIONAL_OPTIONS.filter((opt) =>
        newValues.includes(opt),
      );

      if (selectedRegionalOptions.length > 1) {
        const lastSelected =
          selectedRegionalOptions[selectedRegionalOptions.length - 1];
        const removedRegions = selectedRegionalOptions.slice(0, -1);
        newValues = newValues.filter(
          (v) => v === lastSelected || !main.REGIONAL_OPTIONS.includes(v),
        );
        notifications.push(
          E("p", {}, [
            E("strong", {}, _("Regional options cannot be used together")),
            E("br"),
            _(
              "Warning: %s cannot be used together with %s. Previous selections have been removed.",
            ).format(removedRegions.join(", "), lastSelected),
          ]),
        );
      }

      if (newValues.includes("russia_inside")) {
        const removedServices = newValues.filter(
          (v) => !main.ALLOWED_WITH_RUSSIA_INSIDE.includes(v),
        );
        if (removedServices.length > 0) {
          newValues = newValues.filter((v) =>
            main.ALLOWED_WITH_RUSSIA_INSIDE.includes(v),
          );
          notifications.push(
            E("p", { class: "alert-message warning" }, [
              E("strong", {}, _("Russia inside restrictions")),
              E("br"),
              _(
                "Warning: Russia inside can only be used with %s. %s already in Russia inside and have been removed from selection.",
              ).format(
                main.ALLOWED_WITH_RUSSIA_INSIDE.map(
                  (key) => main.DOMAIN_LIST_OPTIONS[key],
                )
                  .filter((label) => label !== "Russia inside")
                  .join(", "),
                removedServices.join(", "),
              ),
            ]),
          );
        }
      }

      if (JSON.stringify(newValues.sort()) !== JSON.stringify(values.sort())) {
        this.getUIElement(section_id).setValue(newValues);
      }

      notifications.forEach((notification) =>
        ui.addNotification(null, notification),
      );
      lastValues = newValues;
    } catch (e) {
      console.error("Error in onchange handler:", e);
    } finally {
      isProcessing = false;
    }
  };

  o = section.option(
    form.ListValue,
    "user_domain_list_type",
    _("User Domain List Type"),
    _("Select the list type for adding custom domains"),
  );
  o.value("disabled", _("Disabled"));
  o.value("dynamic", _("Dynamic List"));
  o.value("text", _("Text List"));
  o.default = "disabled";
  o.rmempty = false;

  o = section.option(
    form.DynamicList,
    "user_domains",
    _("User Domains"),
    _(
      "Enter domain names without protocols, e.g. example.com or sub.example.com",
    ),
  );
  o.placeholder = "Domains list";
  o.depends("user_domain_list_type", "dynamic");
  o.rmempty = false;
  o.validate = function (section_id, value) {
    // Optional
    if (!value || value.length === 0) {
      return true;
    }

    const validation = main.validateDomain(value, true);

    if (validation.valid) {
      return true;
    }

    return validation.message;
  };

  o = section.option(
    form.TextValue,
    "user_domains_text",
    _("User Domains List"),
    _(
      "Enter domain names separated by commas, spaces, or newlines. You can add comments using //",
    ),
  );
  o.placeholder =
    "example.com, sub.example.com\n// Social networks\ndomain.com test.com // personal domains";
  o.depends("user_domain_list_type", "text");
  o.rows = 8;
  o.rmempty = false;
  o.validate = function (section_id, value) {
    // Optional
    if (!value || value.length === 0) {
      return true;
    }

    const domains = main.parseValueList(value);

    if (!domains.length) {
      return _(
        "At least one valid domain must be specified. Comments-only content is not allowed.",
      );
    }

    const { valid, results } = main.bulkValidate(domains, (row) =>
      main.validateDomain(row, true),
    );

    if (!valid) {
      const errors = results
        .filter((validation) => !validation.valid) // Leave only failed validations
        .map((validation) => `${validation.value}: ${validation.message}`); // Collect validation errors

      return [_("Validation errors:"), ...errors].join("\n");
    }

    return true;
  };

  o = section.option(
    form.ListValue,
    "user_subnet_list_type",
    _("User Subnet List Type"),
    _("Select the list type for adding custom subnets"),
  );
  o.value("disabled", _("Disabled"));
  o.value("dynamic", _("Dynamic List"));
  o.value("text", _("Text List"));
  o.default = "disabled";
  o.rmempty = false;

  o = section.option(
    form.DynamicList,
    "user_subnets",
    _("User Subnets"),
    _(
      "Enter subnets in CIDR notation (e.g. 103.21.244.0/22) or single IP addresses",
    ),
  );
  o.placeholder = "IP or subnet";
  o.depends("user_subnet_list_type", "dynamic");
  o.rmempty = false;
  o.validate = function (section_id, value) {
    // Optional
    if (!value || value.length === 0) {
      return true;
    }

    const validation = main.validateSubnet(value);

    if (validation.valid) {
      return true;
    }

    return validation.message;
  };

  o = section.option(
    form.TextValue,
    "user_subnets_text",
    _("User Subnets List"),
    _(
      "Enter subnets in CIDR notation or single IP addresses, separated by commas, spaces, or newlines. " +
        "You can add comments using //",
    ),
  );
  o.placeholder =
    "103.21.244.0/22\n// Google DNS\n8.8.8.8\n1.1.1.1/32, 9.9.9.9 // Cloudflare and Quad9";
  o.depends("user_subnet_list_type", "text");
  o.rows = 10;
  o.rmempty = false;
  o.validate = function (section_id, value) {
    // Optional
    if (!value || value.length === 0) {
      return true;
    }

    const subnets = main.parseValueList(value);

    if (!subnets.length) {
      return _(
        "At least one valid subnet or IP must be specified. Comments-only content is not allowed.",
      );
    }

    const { valid, results } = main.bulkValidate(subnets, main.validateSubnet);

    if (!valid) {
      const errors = results
        .filter((validation) => !validation.valid) // Leave only failed validations
        .map((validation) => `${validation.value}: ${validation.message}`); // Collect validation errors

      return [_("Validation errors:"), ...errors].join("\n");
    }

    return true;
  };

  o = section.option(
    form.DynamicList,
    "local_domain_lists",
    _("Local Domain Lists"),
    _("Specify the path to the list file located on the router filesystem"),
  );
  o.placeholder = "/path/file.lst";
  o.rmempty = true;
  o.validate = function (section_id, value) {
    // Optional
    if (!value || value.length === 0) {
      return true;
    }

    const validation = main.validatePath(value);

    if (validation.valid) {
      return true;
    }

    return validation.message;
  };

  o = section.option(
    form.DynamicList,
    "local_subnet_lists",
    _("Local Subnet Lists"),
    _("Specify the path to the list file located on the router filesystem"),
  );
  o.placeholder = "/path/file.lst";
  o.rmempty = true;
  o.validate = function (section_id, value) {
    // Optional
    if (!value || value.length === 0) {
      return true;
    }

    const validation = main.validatePath(value);

    if (validation.valid) {
      return true;
    }

    return validation.message;
  };

  o = section.option(
    form.DynamicList,
    "remote_domain_lists",
    _("Remote Domain Lists"),
    _("Specify remote URLs to download and use domain lists"),
  );
  o.placeholder = "https://example.com/domains.srs";
  o.rmempty = true;
  o.validate = function (section_id, value) {
    // Optional
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
    form.DynamicList,
    "remote_subnet_lists",
    _("Remote Subnet Lists"),
    _("Specify remote URLs to download and use subnet lists"),
  );
  o.placeholder = "https://example.com/subnets.srs";
  o.rmempty = true;
  o.validate = function (section_id, value) {
    // Optional
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
    form.DynamicList,
    "fully_routed_ips",
    _("Fully Routed IPs"),
    _(
      "Specify local IP addresses or subnets whose traffic will always be routed through the configured route",
    ),
  );
  o.placeholder = "192.168.1.2 or 192.168.1.0/24";
  o.rmempty = true;
  o.depends("connection_type", "proxy");
  o.depends("connection_type", "vpn");
  o.depends("connection_type", "group");
  o.validate = function (section_id, value) {
    // Optional
    if (!value || value.length === 0) {
      return true;
    }

    const validation = main.validateSubnet(value);

    if (validation.valid) {
      return true;
    }

    return validation.message;
  };

  o = section.option(
    form.Flag,
    "mixed_proxy_enabled",
    _("Enable Mixed Proxy"),
    _(
      "Enable the mixed proxy, allowing this section to route traffic through both HTTP and SOCKS proxies",
    ),
  );
  o.default = "0";
  o.rmempty = false;
  o.depends("connection_type", "proxy");
  o.depends("connection_type", "vpn");
  o.depends("connection_type", "group");

  o = section.option(
    form.Value,
    "mixed_proxy_port",
    _("Mixed Proxy Port"),
    _(
      "Specify the port number on which the mixed proxy will run for this section. " +
        "Make sure the selected port is not used by another service",
    ),
  );
  o.rmempty = false;
  o.depends("mixed_proxy_enabled", "1");

  o = section.option(
    form.Flag,
    "resolve_real_ip_for_routing",
    _("Resolve real IP for routing"),
    _("Enable DNS resolve to get real IP when routing"),
  );
  o.default = "0";
  o.rmempty = false;
  o.depends("connection_type", "proxy");
  o.depends("connection_type", "vpn");
  o.depends("connection_type", "group");
}

const EntryPoint = {
  createSectionContent,
};

return baseclass.extend(EntryPoint);
