"use strict";
"require form";
"require baseclass";
"require uci";
"require view.podkop.main as main";

// The value an option of a group has in the form now: what is being edited, else what is
// saved; a list as a list.
function currentList(section, section_id, option) {
  const value = section.formvalue(section_id, option);
  const list = value != null ? value : uci.get("podkop", section_id, option);
  return L.toArray(list)
    .map((item) => String(item).trim())
    .filter(Boolean);
}

function currentValue(section, section_id, option) {
  const value = section.formvalue(section_id, option);
  return value != null ? value : uci.get("podkop", section_id, option);
}

// The address of a subscription as the form has it now, saved or not: the router knows only
// the saved ones.
function subscriptionAddress(section, name) {
  const found = section.map.lookupOption("url", name);
  if (found) {
    const value = found[0].formvalue(found[1]);
    if (value != null) {
      return String(value).trim();
    }
  }
  return String(uci.get("podkop", name, "url") || "").trim();
}

// What the sections of a group do when it chooses no server, as a line.
function emptyLine(section, section_id) {
  switch (currentValue(section, section_id, "empty") || "all") {
    case "section":
      return _("the sections of the group go as section %s does").format(
        currentValue(section, section_id, "empty_section") || "?",
      );
    case "direct":
      return _("the connections of its sections go directly");
    case "block":
      return _("the connections of its sections are refused");
    default:
      return _("all the servers of its subscriptions are used");
  }
}

// Which servers the group of the form would choose, by the lists the router has.
function renderChosen(section, section_id, preview) {
  const chosen = preview.chosen || [];
  const missing = preview.missing || [];
  const lines = [];
  if (!chosen.length && !preview.total && missing.length) {
    // no list to choose from: why, not what an empty group does
  } else if (chosen.length) {
    lines.push(
      E("details", { class: "pdk-sub-list", open: "" }, [
        E("summary", {}, [
          _("%d of %d servers are chosen").format(chosen.length, preview.total),
        ]),
        E(
          "ul",
          {},
          chosen.map((name) => E("li", {}, [name])),
        ),
      ]),
    );
  } else {
    lines.push(
      E("div", { class: "pdk-sub-error" }, [
        _("No server is chosen (of %d): %s").format(
          preview.total,
          emptyLine(section, section_id),
        ),
      ]),
    );
  }
  missing.forEach((item) => {
    lines.push(
      E("div", { class: "pdk-sub-error" }, [_("No list of %s").format(item)]),
    );
  });
  return E("div", {}, lines);
}

function createGroupContent(section) {
  let o = section.option(
    form.MultiValue,
    "subscription",
    _("Subscriptions"),
    _("The subscriptions the group chooses servers from"),
  );
  // the choices are made for each group as it is drawn: the list of choices is one for all the
  // groups, and what one group adds (a deleted subscription it has) is not the others'
  o.renderWidget = function (section_id, option_index, cfgvalue) {
    this.keylist = [];
    this.vallist = [];
    uci.sections("podkop", "subscription").forEach((item) => {
      this.value(item[".name"], item[".name"]);
    });
    // a list of LuCI with no choice is not drawn at all: the group would not show
    if (!this.keylist.length) {
      this.value("", _("No subscription yet: add one on the tab Subscriptions"));
    }
    // a subscription that is no longer there stays shown, and validate tells why
    L.toArray(cfgvalue).forEach((name) => {
      if (name && !this.keylist.includes(name)) {
        this.value(name, name + " (" + _("deleted") + ")");
      }
    });
    return form.MultiValue.prototype.renderWidget.call(
      this,
      section_id,
      option_index,
      cfgvalue,
    );
  };
  o.rmempty = false;
  // LuCI would refuse an empty choice as "Expecting: non-empty value": validate tells why
  o.optional = true;
  o.validate = function (section_id) {
    const known = uci
      .sections("podkop", "subscription")
      .map((item) => item[".name"]);
    const chosen = currentList(section, section_id, "subscription");
    const gone = chosen.filter((name) => !known.includes(name));
    if (gone.length) {
      return _("There is no subscription %s: choose another one or delete it from the group").format(
        gone.join(", "),
      );
    }
    if (!chosen.length) {
      return known.length
        ? _("Choose a subscription")
        : _("No subscription yet: add one on the tab Subscriptions");
    }
    return true;
  };

  o = section.option(
    form.DynamicList,
    "include",
    _("Name contains"),
    _(
      "A server is chosen when its name contains one of these words, in any case of letters (a flag, a country, a city). None: every server",
    ),
  );
  o.placeholder = "NL";

  o = section.option(
    form.DynamicList,
    "exclude",
    _("Name does not contain"),
    _("A server whose name contains one of these words is never chosen"),
  );

  o = section.option(
    form.ListValue,
    "empty",
    _("When no server is chosen"),
    _(
      "The words choose nothing, or the subscription has no list yet: what the sections of the group do then",
    ),
  );
  o.value("all", _("Use all the servers of the subscriptions"));
  o.value("section", _("Go as another section does"));
  o.value("direct", _("Go directly"));
  o.value("block", _("Refuse the connections"));
  o.default = "all";

  o = section.option(
    form.ListValue,
    "empty_section",
    _("Section"),
    _("The section whose way the connections take"),
  );
  o.depends("empty", "section");
  o.renderWidget = function (section_id, option_index, cfgvalue) {
    this.keylist = [];
    this.vallist = [];
    uci
      .sections("podkop", "section")
      .filter((item) =>
        ["proxy", "vpn", "group"].includes(item.connection_type),
      )
      .forEach((item) => {
        this.value(item[".name"], item[".name"]);
      });
    if (!this.keylist.length) {
      this.value("", _("No section with an outbound yet"));
    }
    // the section chosen before stays shown: one turned block or exclusion is followed (no
    // connection, or directly), one that is no longer there is told by validate
    if (cfgvalue && !this.keylist.includes(cfgvalue)) {
      const type = uci.get("podkop", cfgvalue, "connection_type");
      this.value(cfgvalue, cfgvalue + " (" + (type ? type : _("deleted")) + ")");
    }
    return form.ListValue.prototype.renderWidget.call(
      this,
      section_id,
      option_index,
      cfgvalue,
    );
  };
  o.optional = true;
  o.validate = function (section_id, value) {
    if (currentValue(section, section_id, "empty") !== "section") {
      return true;
    }
    if (!value) {
      return _("Choose a section");
    }
    const found = uci.get("podkop", value);
    if (!found || found[".type"] !== "section") {
      return _("There is no section %s: choose another one").format(value);
    }
    return true;
  };

  // the servers the group of the form chooses, by the lists the router has
  o = section.option(form.DummyValue, "_check", _("Servers"));
  o.rawhtml = true;
  o.cfgvalue = function (section_id) {
    const result = E("div", { class: "pdk-sub-result" }, []);
    const button = E(
      "button",
      {
        class: "cbi-button cbi-button-action",
        click: (ev) => {
          ev.preventDefault();
          const subscriptions = currentList(section, section_id, "subscription");
          if (!subscriptions.length) {
            result.replaceChildren(
              E("div", { class: "pdk-sub-error" }, [_("Choose a subscription")]),
            );
            return;
          }
          button.disabled = true;
          result.replaceChildren(
            E("div", { class: "cbi-value-description" }, [
              _("Asking the router…"),
            ]),
          );
          const addresses = {};
          subscriptions.forEach((name) => {
            addresses[name] = subscriptionAddress(section, name);
          });
          main.PodkopShellMethods.groupCheck({
            subscriptions,
            include: currentList(section, section_id, "include"),
            exclude: currentList(section, section_id, "exclude"),
            addresses,
          })
            .then((response) => {
              result.replaceChildren(
                response.success
                  ? renderChosen(section, section_id, response.data)
                  : E("div", { class: "pdk-sub-error" }, [
                      _("The router did not answer"),
                    ]),
              );
            })
            .finally(() => {
              button.disabled = false;
            });
        },
      },
      [_("Check")],
    );
    return E("div", {}, [button, result]);
  };
}

const EntryPoint = {
  createGroupContent,
};

return baseclass.extend(EntryPoint);
