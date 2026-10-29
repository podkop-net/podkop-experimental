"use strict";
"require form";
"require baseclass";
"require ui";
"require uci";
"require view.podkop.main as main";

// The tab Rules: which sites go through which servers. A rule ("config section") is a row of
// the list, edited in a window with the tabs Main, Servers, Fallback and Extra. Its servers
// and fallbacks are rows of their own ("config member", anonymous, in the order of the file),
// each naming a source of the tab Servers (or direct, or block), the words its servers are
// chosen by, and the source its connections go through.

// the lists Russia inside holds already: podkop does not let them be chosen with it
const IN_RUSSIA_INSIDE = Object.keys(main.DOMAIN_LIST_OPTIONS).filter(
  (key) =>
    !main.ALLOWED_WITH_RUSSIA_INSIDE.includes(key) &&
    !main.REGIONAL_OPTIONS.includes(key),
);

function sourceOf(name) {
  const found = name ? uci.get("podkop", name) : null;
  return found && found[".type"] === "source" ? found : null;
}

function ruleLabel(name) {
  const rule = uci.get("podkop", name);
  return (rule && String(rule.label || "").trim()) || name;
}

function listLabel(key) {
  return main.DOMAIN_LIST_OPTIONS[key] || key;
}

// the rows of a rule in the order of the file, the servers or the fallbacks
function rowsOf(rule, role) {
  return uci
    .sections("podkop", "member")
    .filter(
      (row) =>
        row.section === rule &&
        (row.role === "fallback") === (role === "fallback"),
    );
}

// A row as a line of the list: its source, its words, the source it goes through
function rowText(row) {
  if (row.source === main.ROW_DIRECT) {
    return _("Directly");
  }
  if (row.source === main.ROW_BLOCK) {
    return _("Block");
  }
  const item = sourceOf(row.source);
  let text;
  if (!item) {
    text = _("%s (deleted)").format(row.source || "?");
  } else {
    text = main.sourceLabel(item);
    if (!main.sourceFilled(item)) {
      text += " (" + _("not filled") + ")";
    } else if (main.isMultiServer(item)) {
      const words = [];
      const include = main.filterWords(row.include);
      const exclude = main.filterWords(row.exclude);
      if (include.length) {
        words.push(include.join(", "));
      }
      if (exclude.length) {
        words.push(_("without %s").format(exclude.join(", ")));
      }
      if (words.length) {
        text += ": " + words.join(", ");
      }
    }
  }
  if (row.via) {
    const via = sourceOf(row.via);
    text +=
      " " +
      _("via %s").format(
        via ? main.sourceLabel(via) : _("%s (deleted)").format(row.via),
      );
  }
  return text;
}

// The lists of a rule, short, and the lists a rule above takes first
function listsLines(grid, section_id) {
  const rule = uci.get("podkop", section_id) || {};
  const lists = L.toArray(rule.community_lists);
  const parts = lists.map(listLabel);
  const count = (option) => L.toArray(rule[option]).length;
  if (
    (rule.user_domain_list_type === "dynamic" && count("user_domains")) ||
    (rule.user_domain_list_type === "text" &&
      String(rule.user_domains_text || "").trim())
  ) {
    parts.push(_("own domains"));
  }
  if (
    (rule.user_subnet_list_type === "dynamic" && count("user_subnets")) ||
    (rule.user_subnet_list_type === "text" &&
      String(rule.user_subnets_text || "").trim())
  ) {
    parts.push(_("own subnets"));
  }
  const byLink =
    count("remote_domain_lists") +
    count("local_domain_lists") +
    count("remote_subnet_lists") +
    count("local_subnet_lists");
  if (byLink) {
    parts.push(_("lists by link: %d").format(byLink));
  }
  if (count("fully_routed_ips")) {
    parts.push(_("fully routed IPs: %d").format(count("fully_routed_ips")));
  }
  const lines = [parts.join(", ") || _("no lists")];
  if (rule.enabled === "0") {
    return lines;
  }
  const order = grid.cfgsections();
  for (const above of order.slice(0, order.indexOf(section_id))) {
    const upper = uci.get("podkop", above) || {};
    if (upper.enabled === "0") {
      continue;
    }
    const upperLists = L.toArray(upper.community_lists);
    lists.forEach((key) => {
      if (upperLists.includes(key)) {
        lines.push(
          _("%s is in the rule %s above already").format(
            listLabel(key),
            ruleLabel(above),
          ),
        );
      } else if (
        upperLists.includes("russia_inside") &&
        IN_RUSSIA_INSIDE.includes(key)
      ) {
        lines.push(
          _("%s is in Russia inside of the rule %s above").format(
            listLabel(key),
            ruleLabel(above),
          ),
        );
      }
    });
  }
  return lines;
}

// A rule added on the page gets a row of the servers: the first source that is filled, else the
// first one
function ruleAdded(name) {
  const sources = uci.sections("podkop", "source");
  const first = sources.find((item) => main.sourceFilled(item)) || sources[0];
  if (!first) {
    return;
  }
  const row = uci.add("podkop", "member");
  uci.set("podkop", row, "section", name);
  uci.set("podkop", row, "role", "server");
  uci.set("podkop", row, "source", first[".name"]);
}

// A rule deleted takes its rows with it: a rule given its name later would get them
function ruleRemoved(name) {
  uci
    .sections("podkop", "member")
    .filter((row) => row.section === name)
    .forEach((row) => uci.remove("podkop", row[".name"]));
}

// The rows of a window are added and removed as LuCI does it for a table in a window (the
// window's form is staged and drawn again), but a field that does not pass its check does not
// stop it. The window is marked, so that its dismissal draws the page again.
function stageWindow(map) {
  map.pdkStaged = true;
  map.checkDepends();
  return Promise.resolve(map.parse())
    .catch(() => {})
    .then(() => map.data.save())
    .then(() => map.load())
    .then(() => map.renderContents());
}

// The value an option of a row has in the window now: what is being edited, else what is
// staged
function rowValue(table, section_id, option) {
  const value = table.formvalue(section_id, option);
  return value != null ? value : uci.get("podkop", section_id, option);
}

// What the servers of a row are: how many of the servers of its source its words take. A
// subscription is asked of the router (its list is there); links are counted here.
function refreshMatched(table, section_id) {
  const node = table.pdkMatched && table.pdkMatched[section_id];
  if (!node) {
    return;
  }
  table.pdkTokens = table.pdkTokens || {};
  const token = (table.pdkTokens[section_id] || 0) + 1;
  table.pdkTokens[section_id] = token;
  const show = (text, title) => {
    if (table.pdkTokens[section_id] === token) {
      node.textContent = text;
      node.title = title || "";
    }
  };
  const name = rowValue(table, section_id, "source");
  if (!name || name === main.ROW_DIRECT || name === main.ROW_BLOCK) {
    return show("");
  }
  const item = sourceOf(name);
  if (!item) {
    return show(_("source deleted"));
  }
  if (!main.sourceFilled(item)) {
    return show(_("not filled"));
  }
  if (!main.isMultiServer(item)) {
    return show("1");
  }
  const include = main.filterWords(rowValue(table, section_id, "include"));
  const exclude = main.filterWords(rowValue(table, section_id, "exclude"));
  const counted = (chosen, total) =>
    show(
      chosen.length
        ? _("%d of %d").format(chosen.length, total)
        : _("0 of %d, check the words").format(total),
      chosen.join(", "),
    );
  if (main.sourceKind(item) === "links") {
    const names = main.sourceServerNames(item);
    return counted(
      names.filter((server) => main.rowTakes(server, include, exclude)),
      names.length,
    );
  }
  show(_("asking…"));
  clearTimeout(table.pdkTimers && table.pdkTimers[section_id]);
  table.pdkTimers = table.pdkTimers || {};
  table.pdkTimers[section_id] = setTimeout(() => {
    main.PodkopShellMethods.groupCheck({
      subscriptions: [name],
      include,
      exclude,
      addresses: { [name]: String(item.url || "").trim() },
    }).then((response) => {
      if (!response.success || !response.data) {
        return show(_("The router did not answer"));
      }
      const preview = response.data;
      if (!preview.total && preview.missing && preview.missing.length) {
        return show(_("no list yet"), preview.missing.join("; "));
      }
      counted(preview.chosen || [], preview.total || 0);
    });
  }, 300);
}

// a source with several servers is connected through the best of them (a URL test)
function viaLabel(item) {
  return main.isMultiServer(item)
    ? _("best of %s").format(main.sourceLabel(item))
    : main.sourceLabel(item);
}

// The table of the rows of one role in the window of a rule: the rows whose section is the
// rule. The table is told the rule by the option that holds it (load, parse, render).
function rowsTable(section, tab, option, role, description, placeholder) {
  const o = section.taboption(
    tab,
    form.SectionValue,
    option,
    form.TableSection,
    "member",
    null,
    description,
  );
  o.modalonly = true;
  const table = o.subsection;
  table.anonymous = true;
  table.addremove = true;
  table.sortable = true;
  table.nodescriptions = true;
  table.role = role;
  ["load", "parse", "render", "checkDepends"].forEach((method) => {
    const base = form.TableSection.prototype[method];
    table[method] = function (rule, ...rest) {
      if (typeof rule === "string") {
        this.rule = rule;
      }
      return base.call(this, rule, ...rest);
    };
  });
  table.filter = function (section_id) {
    return (
      this.rule != null &&
      uci.get("podkop", section_id, "section") === this.rule &&
      (uci.get("podkop", section_id, "role") === "fallback") ===
        (this.role === "fallback")
    );
  };
  // the order is the order of the servers and of the fallbacks: dragging only
  table.handleSort = function () {};
  table.renderSectionPlaceholder = function () {
    return E("em", {}, [placeholder]);
  };
  table.handleAdd = function () {
    const first = uci.sections("podkop", "source")[0];
    const row = uci.add("podkop", "member");
    uci.set("podkop", row, "section", this.rule);
    uci.set("podkop", row, "role", this.role);
    uci.set("podkop", row, "source", first ? first[".name"] : main.ROW_DIRECT);
    return stageWindow(this.map);
  };
  table.handleRemove = function (section_id) {
    uci.remove("podkop", section_id);
    return stageWindow(this.map);
  };

  let column = table.option(form.ListValue, "source", _("Source"));
  column.rmempty = false;
  column.renderWidget = function (section_id, option_index, cfgvalue) {
    this.keylist = [];
    this.vallist = [];
    uci.sections("podkop", "source").forEach((item) => {
      this.value(
        item[".name"],
        main.sourceLabel(item) +
          (main.sourceFilled(item) ? "" : " (" + _("not filled") + ")"),
      );
    });
    this.value(main.ROW_DIRECT, _("Directly"));
    this.value(main.ROW_BLOCK, _("Block"));
    // a source that is no longer there stays shown, and validate tells why
    if (cfgvalue && !this.keylist.includes(cfgvalue)) {
      this.value(cfgvalue, _("%s (deleted)").format(cfgvalue));
    }
    return form.ListValue.prototype.renderWidget.call(
      this,
      section_id,
      option_index,
      cfgvalue,
    );
  };
  column.validate = function (section_id, value) {
    if (value && !main.RESERVED_NAMES.includes(value) && !sourceOf(value)) {
      return _("The source %s is deleted: choose another one").format(value);
    }
    return true;
  };
  column.onchange = function (ev, section_id) {
    refreshMatched(this.section, section_id);
  };

  // the words of a filter, by commas; a list of the settings
  const words = (name, title, placeholderText) => {
    const field = table.option(form.Value, name, title);
    field.placeholder = placeholderText;
    field.load = function (section_id) {
      return main.filterWords(uci.get("podkop", section_id, name)).join(", ");
    };
    field.write = function (section_id, value) {
      const list = main.filterWords(value);
      return list.length
        ? uci.set("podkop", section_id, name, list)
        : uci.unset("podkop", section_id, name);
    };
    field.remove = function (section_id) {
      return uci.unset("podkop", section_id, name);
    };
    // only the servers of a subscription or of several links are chosen by their names
    field.checkDepends = function (section_id) {
      return main.isMultiServer(
        sourceOf(rowValue(this.section, section_id, "source")),
      );
    };
    field.onchange = function (ev, section_id) {
      refreshMatched(this.section, section_id);
    };
    return field;
  };
  words("include", _("Name contains"), _("all"));
  words("exclude", _("Name does not contain"), "");

  column = table.option(form.ListValue, "via", _("Through"));
  column.renderWidget = function (section_id, option_index, cfgvalue) {
    this.keylist = [];
    this.vallist = [];
    this.value("", _("directly"));
    uci.sections("podkop", "source").forEach((item) => {
      if (main.sourceFilled(item) && main.sourceKind(item)) {
        this.value(item[".name"], viaLabel(item));
      }
    });
    if (cfgvalue && !this.keylist.includes(cfgvalue)) {
      const item = sourceOf(cfgvalue);
      this.value(
        cfgvalue,
        item
          ? viaLabel(item) + " (" + _("not filled") + ")"
          : _("%s (deleted)").format(cfgvalue),
      );
    }
    return form.ListValue.prototype.renderWidget.call(
      this,
      section_id,
      option_index,
      cfgvalue,
    );
  };
  // the servers of an interface go out through it, never through another source
  column.checkDepends = function (section_id) {
    const name = rowValue(this.section, section_id, "source");
    if (!name || main.RESERVED_NAMES.includes(name)) {
      return false;
    }
    return main.sourceKind(sourceOf(name)) !== "interface";
  };
  column.validate = function (section_id, value) {
    if (!value) {
      return true;
    }
    if (value === rowValue(this.section, section_id, "source")) {
      return _("A row cannot connect through its own source");
    }
    const item = sourceOf(value);
    if (!item) {
      return _("The source %s is deleted: choose another one").format(value);
    }
    if (!main.sourceFilled(item)) {
      return _("The source %s is not filled yet").format(
        main.sourceLabel(item),
      );
    }
    return true;
  };

  column = table.option(form.DummyValue, "_matched", _("Matched"));
  column.rawhtml = true;
  column.cfgvalue = function (section_id) {
    // a load sets the value (two arguments): only a row drawn is counted
    if (arguments.length > 1) {
      return null;
    }
    const node = E("span", {}, [""]);
    this.section.pdkMatched = this.section.pdkMatched || {};
    this.section.pdkMatched[section_id] = node;
    refreshMatched(this.section, section_id);
    return node;
  };
  // nothing to save, and a parse must not count again
  column.parse = function () {
    return Promise.resolve();
  };
  return o;
}

// A field of lists by link: a link https:// is downloaded (remote), a path /… is read from a
// file on the router (local). One field of the window, two lists of the settings.
function linksField(section, option, title, remote, local, placeholder) {
  const o = section.taboption(
    "main",
    form.DynamicList,
    option,
    title,
    _(
      "A link https:// is downloaded, a path /… is read from a file on the router",
    ),
  );
  o.modalonly = true;
  o.placeholder = placeholder;
  o.load = function (section_id) {
    return [
      ...L.toArray(uci.get("podkop", section_id, remote)),
      ...L.toArray(uci.get("podkop", section_id, local)),
    ];
  };
  o.validate = function (section_id, value) {
    if (!value || value.length === 0) {
      return true;
    }
    const validation = value.startsWith("/")
      ? main.validatePath(value)
      : main.validateUrl(value);
    return validation.valid ? true : validation.message;
  };
  const put = (section_id, name, list) =>
    list.length
      ? uci.set("podkop", section_id, name, list)
      : uci.unset("podkop", section_id, name);
  o.write = function (section_id, value) {
    const list = L.toArray(value);
    put(
      section_id,
      remote,
      list.filter((item) => !item.startsWith("/")),
    );
    put(
      section_id,
      local,
      list.filter((item) => item.startsWith("/")),
    );
  };
  o.remove = function (section_id) {
    uci.unset("podkop", section_id, remote);
    uci.unset("podkop", section_id, local);
  };
  return o;
}

function createRulesContent(section, singBoxFeatures = []) {
  section.modaltitle = function (section_id) {
    return _("Rules") + " » " + ruleLabel(section_id);
  };
  // the order of the rules is the order of their route rules: dragging only
  section.handleSort = function () {};
  section.renderSectionPlaceholder = function () {
    return E("em", {}, [_("No rule yet: press Add")]);
  };

  section.tab("main", _("Main"));
  section.tab("servers", _("Servers"));
  if (singBoxFeatures.includes("urltest.fallbacks")) {
    section.tab("fallback", _("Fallback"));
  }
  section.tab("extra", _("Extra"));

  // the columns of the list
  let o = section.option(form.Flag, "enabled", _("On"));
  o.modalonly = false;
  o.editable = true;
  o.default = "1";
  o.rmempty = false;

  o = section.option(form.DummyValue, "_label", _("Name"));
  o.modalonly = false;
  o.textvalue = function (section_id) {
    return E("strong", {}, [ruleLabel(section_id)]);
  };

  o = section.option(form.DummyValue, "_lists", _("Lists"));
  o.modalonly = false;
  o.textvalue = function (section_id) {
    const [first, ...notes] = listsLines(this.section, section_id);
    return E("div", {}, [
      E("div", {}, [first]),
      ...notes.map((note) => E("div", {}, [E("em", {}, [note])])),
    ]);
  };

  o = section.option(form.DummyValue, "_rows", _("Servers"));
  o.modalonly = false;
  o.textvalue = function (section_id) {
    const servers = rowsOf(section_id, "server").map(rowText);
    const fallbacks = rowsOf(section_id, "fallback").map(rowText);
    const lines = [
      E("div", {}, [
        servers.join("; ") || _("No servers: the rule does nothing"),
      ]),
    ];
    if (fallbacks.length) {
      lines.push(
        E("div", {}, [
          E("em", {}, [_("Fallback: %s").format(fallbacks.join("; "))]),
        ]),
      );
    }
    return E("div", {}, lines);
  };

  // the tab Main: the name and the lists
  o = section.taboption(
    "main",
    form.Value,
    "label",
    _("Name"),
    _("Empty: the name in the settings"),
  );
  o.modalonly = true;
  o.renderWidget = function (section_id, option_index, cfgvalue) {
    this.placeholder = section_id;
    return form.Value.prototype.renderWidget.call(
      this,
      section_id,
      option_index,
      cfgvalue,
    );
  };
  o.validate = function (section_id, value) {
    return String(value || "").length > 64 ? _("At most 64 characters") : true;
  };

  o = section.taboption(
    "main",
    form.DynamicList,
    "community_lists",
    _("Community Lists"),
    _("Select a predefined list for routing") +
      ' <a href="https://github.com/itdoginfo/allow-domains" target="_blank" rel="noopener noreferrer">github.com/itdoginfo/allow-domains</a>',
  );
  o.modalonly = true;
  o.placeholder = "Service list";
  Object.entries(main.DOMAIN_LIST_OPTIONS).forEach(([key, label]) => {
    o.value(key, _(label));
  });
  o.rmempty = true;
  let isProcessing = false;
  o.onchange = function (ev, section_id, value) {
    if (isProcessing) return;
    isProcessing = true;

    try {
      const values = Array.isArray(value) ? value : [value];
      let newValues = [...values];
      const notifications = [];

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
            E("p", {}, [
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

      if (
        JSON.stringify([...newValues].sort()) !==
        JSON.stringify([...values].sort())
      ) {
        this.getUIElement(section_id).setValue(newValues);
      }

      // the window covers the page: what was taken off is told in the window, under the field
      const frame = this.map.findElement(
        "id",
        "cbi-podkop-" + section_id + "-community_lists",
      );
      const field = frame ? frame.querySelector(".cbi-value-field") : null;
      if (field) {
        field
          .querySelectorAll(".pdk-lists-note")
          .forEach((node) => node.remove());
        notifications.forEach((notification) => {
          notification.classList.add("pdk-lists-note", "cbi-value-description");
          field.appendChild(notification);
        });
      } else {
        notifications.forEach((notification) =>
          ui.addNotification(null, notification),
        );
      }
    } catch (e) {
      console.error("Error in onchange handler:", e);
    } finally {
      isProcessing = false;
    }
  };

  o = section.taboption(
    "main",
    form.ListValue,
    "user_domain_list_type",
    _("User Domain List Type"),
    _("Select the list type for adding custom domains"),
  );
  o.modalonly = true;
  o.value("disabled", _("Disabled"));
  o.value("dynamic", _("Dynamic List"));
  o.value("text", _("Text List"));
  o.default = "disabled";
  o.rmempty = false;

  o = section.taboption(
    "main",
    form.DynamicList,
    "user_domains",
    _("User Domains"),
    _(
      "Enter domain names without protocols, e.g. example.com or sub.example.com",
    ),
  );
  o.modalonly = true;
  o.placeholder = "Domains list";
  o.depends("user_domain_list_type", "dynamic");
  o.rmempty = false;
  o.validate = function (section_id, value) {
    if (!value || value.length === 0) {
      return true;
    }
    const validation = main.validateDomain(value, true);
    return validation.valid ? true : validation.message;
  };

  o = section.taboption(
    "main",
    form.TextValue,
    "user_domains_text",
    _("User Domains List"),
    _(
      "Enter domain names separated by commas, spaces, or newlines. You can add comments using //",
    ),
  );
  o.modalonly = true;
  o.placeholder =
    "example.com, sub.example.com\n// Social networks\ndomain.com test.com // personal domains";
  o.depends("user_domain_list_type", "text");
  o.rows = 8;
  o.rmempty = false;
  o.validate = function (section_id, value) {
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
        .filter((validation) => !validation.valid)
        .map((validation) => `${validation.value}: ${validation.message}`);
      return [_("Validation errors:"), ...errors].join("\n");
    }
    return true;
  };

  linksField(
    section,
    "_domain_links",
    _("Domains by link"),
    "remote_domain_lists",
    "local_domain_lists",
    "https://example.com/domains.srs",
  );

  o = section.taboption(
    "main",
    form.ListValue,
    "user_subnet_list_type",
    _("User Subnet List Type"),
    _("Select the list type for adding custom subnets"),
  );
  o.modalonly = true;
  o.value("disabled", _("Disabled"));
  o.value("dynamic", _("Dynamic List"));
  o.value("text", _("Text List"));
  o.default = "disabled";
  o.rmempty = false;

  o = section.taboption(
    "main",
    form.DynamicList,
    "user_subnets",
    _("User Subnets"),
    _(
      "Enter subnets in CIDR notation (e.g. 103.21.244.0/22) or single IP addresses",
    ),
  );
  o.modalonly = true;
  o.placeholder = "IP or subnet";
  o.depends("user_subnet_list_type", "dynamic");
  o.rmempty = false;
  o.validate = function (section_id, value) {
    if (!value || value.length === 0) {
      return true;
    }
    const validation = main.validateSubnet(value);
    return validation.valid ? true : validation.message;
  };

  o = section.taboption(
    "main",
    form.TextValue,
    "user_subnets_text",
    _("User Subnets List"),
    _(
      "Enter subnets in CIDR notation or single IP addresses, separated by commas, spaces, or newlines. You can add comments using //",
    ),
  );
  o.modalonly = true;
  o.placeholder =
    "103.21.244.0/22\n// Google DNS\n8.8.8.8\n1.1.1.1/32, 9.9.9.9 // Cloudflare and Quad9";
  o.depends("user_subnet_list_type", "text");
  o.rows = 10;
  o.rmempty = false;
  o.validate = function (section_id, value) {
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
        .filter((validation) => !validation.valid)
        .map((validation) => `${validation.value}: ${validation.message}`);
      return [_("Validation errors:"), ...errors].join("\n");
    }
    return true;
  };

  linksField(
    section,
    "_subnet_links",
    _("Subnets by link"),
    "remote_subnet_lists",
    "local_subnet_lists",
    "https://example.com/subnets.srs",
  );

  o = section.taboption(
    "main",
    form.DynamicList,
    "fully_routed_ips",
    _("Fully Routed IPs"),
    _("All the traffic of these devices of the network goes by this rule"),
  );
  o.modalonly = true;
  o.placeholder = "192.168.1.2 or 192.168.1.0/24";
  o.rmempty = true;
  o.validate = function (section_id, value) {
    if (!value || value.length === 0) {
      return true;
    }
    const validation = main.validateSubnet(value);
    return validation.valid ? true : validation.message;
  };

  // the tabs Servers and Fallback: rows of their own
  rowsTable(
    section,
    "servers",
    "_servers",
    "server",
    _(
      "The fastest of all the servers of these rows is used. Words of a filter go by commas; a word finds the start of a word of the name: “AI” finds “USA AI-1”, but not “Spain”. Directly or Block works here only as the one row.",
    ),
    _("No servers: the rule does nothing"),
  );
  if (singBoxFeatures.includes("urltest.fallbacks")) {
    rowsTable(
      section,
      "fallback",
      "_fallbacks",
      "fallback",
      _(
        "In this order, while no server of the rule answers. Directly here: blocked sites do not open, and the provider sees the addresses.",
      ),
      _("No fallbacks"),
    );
  }

  // the tab Extra
  o = section.taboption(
    "extra",
    form.Flag,
    "mixed_proxy_enabled",
    _("Enable Mixed Proxy"),
    _(
      "HTTP and SOCKS on this port of the router go through the servers of this rule",
    ),
  );
  o.modalonly = true;
  o.default = "0";
  o.rmempty = false;

  o = section.taboption(
    "extra",
    form.Value,
    "mixed_proxy_port",
    _("Mixed Proxy Port"),
    _("Make sure the port is not used by another service"),
  );
  o.modalonly = true;
  o.datatype = "port";
  o.placeholder = "2080";
  o.rmempty = false;
  o.depends("mixed_proxy_enabled", "1");

  o = section.taboption(
    "extra",
    form.Flag,
    "resolve_real_ip_for_routing",
    _("Resolve real IP for routing"),
    _(
      "A domain is resolved to its real IP before the rule is chosen, so that the lists of subnets match",
    ),
  );
  o.modalonly = true;
  o.default = "0";
  o.rmempty = false;
}

const EntryPoint = {
  createRulesContent,
  ruleAdded,
  ruleRemoved,
};

return baseclass.extend(EntryPoint);
