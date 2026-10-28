"use strict";
"require form";
"require baseclass";
"require uci";
"require view.podkop.main as main";

// The value an option of a subscription has in the form now: what is being edited, else
// what is saved.
function currentValue(section, section_id, option) {
  const value = section.formvalue(section_id, option);
  return value != null ? value : uci.get("podkop", section_id, option);
}

// The state of the subscriptions as the router knows them, asked once a render of the tab.
let states = null;
function subscriptionStates() {
  if (!states) {
    states = main.PodkopShellMethods.subscriptionStatus().then((response) =>
      response.success && Array.isArray(response.data) ? response.data : [],
    );
  }
  return states;
}

// The language of the page for dates and times: LuCI's, as the browser writes it (zh_Hans
// is zh-Hans); none when the browser does not know it, and the browser's own is used.
const language = (() => {
  const lang = String(document.documentElement.lang || "").replace(/_/g, "-");
  try {
    new Intl.DateTimeFormat(lang || undefined);
    return lang || undefined;
  } catch (e) {
    return undefined;
  }
})();

function relative(value, unit, numeric) {
  try {
    return new Intl.RelativeTimeFormat(language, {
      numeric: numeric || "always",
    }).format(value, unit);
  } catch (e) {
    return value + " " + unit;
  }
}

function calendarDays(time, base) {
  const day = (date) =>
    Date.UTC(date.getFullYear(), date.getMonth(), date.getDate());
  return Math.round((day(time) - day(base)) / 86400000);
}

// When a time of the router was or will be, short, against the clock of the router: "just
// now", "10 minutes ago (18:21)", "today at 18:31", "28 Oct, 14:39".
function when(text, now) {
  const time = new Date(text);
  if (isNaN(time)) {
    return text;
  }
  const base = now && !isNaN(new Date(now)) ? new Date(now) : new Date();
  const ahead = time - base;
  const clock = time.toLocaleTimeString(language, {
    hour: "2-digit",
    minute: "2-digit",
  });
  if (Math.abs(ahead) < 60000) {
    return _("just now");
  }
  if (Math.abs(ahead) < 3600000) {
    return relative(Math.round(ahead / 60000), "minute") + " (" + clock + ")";
  }
  const days = calendarDays(time, base);
  if (Math.abs(days) <= 1) {
    return _("%s at %s").format(relative(days, "day", "auto"), clock);
  }
  const options = { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" };
  if (time.getFullYear() !== base.getFullYear()) {
    options.year = "numeric";
  }
  return time.toLocaleString(language, options);
}

// A time with its full date in the tooltip.
function timeOf(text, now) {
  const time = new Date(text);
  return E(
    "span",
    { title: isNaN(time) ? "" : time.toLocaleString(language) },
    [when(text, now)],
  );
}

// A line of a translated text with nodes in the places of its %s, in order: the words around
// a time stay where the translation puts them.
function lineWith(template, ...nodes) {
  const parts = template.split("%s");
  const children = [];
  parts.forEach((part, index) => {
    if (part) {
      children.push(part);
    }
    if (index < parts.length - 1 && index < nodes.length) {
      children.push(nodes[index]);
    }
  });
  return E("div", {}, children);
}

// Bytes in binary units, as the traffic of panels is counted: "37.25 GiB", "100 GiB".
function bytes(amount) {
  return "%1024.2mB"
    .format(amount || 0)
    .replace(/\.(\d*?)0+(?=\s)/, (match, digits) => (digits ? "." + digits : ""));
}

function seconds(ms) {
  return (Math.round((ms || 0) / 100) / 10).toLocaleString(language);
}

// The way a list came or is tried by, as words.
function wayOf(route) {
  return route === "direct" ? _("directly") : _("through %s").format(route);
}

// Why a try of a download failed, by its code; the English text of the router for a code
// this page does not know.
function tryReason(attempt) {
  const args = attempt.args || [];
  switch (attempt.code) {
    case "timeout":
      return _("no answer in %d s").format(+args[0] || 0);
    case "connect-timeout":
      return _("no connection in %d s").format(+args[0] || 0);
    case "tls-timeout":
      return _("no secure connection in %d s").format(+args[0] || 0);
    case "plain-redirect":
      return _("the provider redirects to plain HTTP, which goes directly only");
    case "stalled":
      return _("the transfer stopped at %s").format(bytes(attempt.bytes || (+args[0] || 0) * 1024));
    case "dns":
      return _("the name is not found in DNS");
    case "refused-connection":
      return _("the connection is refused");
    case "reset":
      return _("the connection is reset");
    case "tls":
      return _("the secure connection failed");
    case "cert":
      return _("the certificate is not valid by the router's clock: check the clock");
    case "page":
      return _("a web page instead of the list");
    case "blocked":
      return _("blocked on the way (HTTP 451)");
    case "cut":
      return _("the list broke off");
    case "status":
      return "HTTP " + args[0];
    case "canceled":
      return _("another way brought the list first");
  }
  return attempt.error || "";
}

// Why a download came to nothing, by its code, with the tries that did not bring it.
function failureText(code, args, text, attempts) {
  args = args || [];
  const said = (base) =>
    args[0] ? base + ". " + _("The provider says: %s").format(args[0]) : base;
  switch (code) {
    case "unreachable": {
      const reasons = (attempts || [])
        .filter((attempt) => attempt.code !== "canceled")
        .map((attempt) => wayOf(attempt.route) + ": " + tryReason(attempt));
      return _("The provider could not be reached (%s)").format(reasons.join("; "));
    }
    case "status-one": {
      // the status may be that of a CDN to the address of the one way that got it
      const reasons = (attempts || [])
        .filter((attempt) => attempt.code !== "canceled" && attempt.code !== "status")
        .map((attempt) => wayOf(attempt.route) + ": " + tryReason(attempt));
      return _("HTTP %s came by one way only (%s); the other ways did not reach the provider (%s)").format(
        args[0],
        wayOf(args[1]),
        reasons.join("; "),
      );
    }
    case "page":
      return _("A web page came instead of the list: it may be the address of the provider's site, not of the subscription, or a page of the ISP");
    case "refused":
      return _("The provider refused the address (HTTP %s): it is wrong or out of date, or the subscription is blocked").format(args[0]);
    case "notfound":
      return _("The provider has no subscription at this address (HTTP %s): the address is wrong, or the subscription was removed").format(args[0]);
    case "nocontent":
      return _("The provider sent nothing (HTTP 204): the address is wrong, or the subscription was removed");
    case "wait":
      return _("The provider asks to wait (HTTP 429): the router tries again later");
    case "server":
      return _("The provider's server failed (HTTP %s): the router tries again later").format(args[0]);
    case "http":
      return _("The provider answered HTTP %s instead of the list").format(args[0]);
    case "hwid":
      return said(_("The provider did not accept this device (HWID)"));
    case "devices":
      return said(_("The provider's limit of devices is reached: delete an old device in the provider's bot or account, then check again"));
    case "toobig":
      return _("The list is larger than %s MiB").format(args[0]);
    case "empty":
      return _("The provider sent an empty list");
    case "nolinks":
      return _("The answer of the provider has no links of servers");
    case "json":
      return _("The provider sent a configuration in JSON (sing-box or Xray): podkop reads only a list of links so far");
    case "clash":
      return _("The provider sent a configuration of Clash (YAML): podkop reads only a list of links so far");
    case "placeholder":
      return _("The provider sent notes instead of servers: %s").format(args[0]);
    case "address":
      return _("An address of HTTP or HTTPS is expected");
    case "noway":
      return _("There is no way to the provider to try");
    case "fault":
      return _("The download stopped on a fault of podkop: see the log");
    case "notrunning":
      return _("podkop is not running: start it to load the list");
    case "nojob":
      return _("The download is lost: podkop restarted, or it ended long ago. Press Load again");
    case "busy":
      return _("Two lists are being downloaded for the page: wait for them");
    case "canceled":
      return _("The download was canceled");
  }
  return text || "";
}

// A try as a line: the way, and how far it came or why it failed.
function attemptLine(attempt) {
  let progress;
  switch (attempt.phase) {
    case "connect":
      progress = _("connecting…");
      break;
    case "tls":
      progress = _("secure connection…");
      break;
    case "wait":
      progress = _("waiting for the provider: %s s").format(seconds(attempt.ms));
      break;
    case "body":
      progress = _("%s received").format(bytes(attempt.bytes));
      break;
    case "done":
      progress = _("done in %s s").format(seconds(attempt.ms));
      break;
    default:
      progress = tryReason(attempt);
  }
  return wayOf(attempt.route) + " — " + progress;
}

// What the router knows of a subscription, a line a fact: its servers, the last check and its
// way, when its servers changed, the next check; a failure with the list kept.
function stateBlock(state) {
  if (!state) {
    return [_("Not downloaded yet: save the settings, the router downloads the list then")];
  }
  const now = state.now;
  const lines = [];
  if (state.changed) {
    lines.push(_("Servers: %d, usable: %d").format(state.servers, state.usable));
  }
  if (state.busy) {
    lines.push(_("Checking now…"));
  }
  const failed = !!state.error;
  if (failed) {
    lines.push(lineWith(_("Last check: %s, failed"), timeOf(state.attempted || state.next, now)));
    lines.push(
      E("div", { class: "pdk-sub-error" }, [
        failureText(state.error_code, state.error_args, state.error, state.attempts),
      ]),
    );
    if (state.changed) {
      lines.push(lineWith(_("The list from %s stays in use"), timeOf(state.changed, now)));
    } else {
      lines.push(_("No list yet: the groups of the subscription go by their rule for no server"));
    }
  } else if (state.checked) {
    const took = state.took_ms >= 100 ? ", " + _("%s s").format(seconds(state.took_ms)) : "";
    lines.push(lineWith(_("Last check: %s, %s"), timeOf(state.checked, now), wayOf(state.route) + took));
  } else if (state.changed) {
    lines.push(_("Last check: none since podkop started"));
  } else {
    lines.push(_("The list is not downloaded yet"));
  }
  if (state.changed) {
    lines.push(lineWith(_("Servers changed: %s"), timeOf(state.changed, now)));
  }
  if (state.next && !state.busy) {
    lines.push(lineWith(failed ? _("Next try: %s") : _("Next check: %s"), timeOf(state.next, now)));
  }
  return lines;
}

// What the provider told of a subscription: its title, the traffic, the end, the reset, its
// pages, its notice. stale: the time of the list the data came with, when it is not of a
// fresh check.
function providerBlock(info, stale) {
  if (!info) {
    return null;
  }
  const lines = [E("strong", {}, [_("From the provider")])];
  if (info.title) {
    lines.push(E("div", {}, [_("Name at the provider: %s").format(info.title)]));
  }
  let ended = false;
  if (info.traffic) {
    const used = (info.upload || 0) + (info.download || 0);
    if (info.total) {
      const share = Math.min(100, Math.round((used / info.total) * 100));
      const usedUp = used >= info.total;
      ended = ended || usedUp;
      lines.push(
        E("div", { class: usedUp ? "pdk-sub-error" : share >= 90 ? "pdk-sub-warn" : "" }, [
          (usedUp ? _("Traffic: %s of %s, used up") : _("Traffic: %s of %s")).format(
            bytes(used),
            bytes(info.total),
          ),
        ]),
      );
      lines.push(
        E(
          "div",
          {
            class: "cbi-progressbar",
            title: "%s / %s (%d%%)".format(bytes(used), bytes(info.total), share),
          },
          E("div", { style: "width:%d%%".format(share) }),
        ),
      );
    } else {
      lines.push(E("div", {}, [_("Traffic: %s, no limit").format(bytes(used))]));
    }
  }
  if (info.expire) {
    const end = new Date(info.expire);
    const days = calendarDays(end, new Date());
    const date = end.toLocaleDateString(language, { dateStyle: "medium" });
    if (end <= new Date()) {
      ended = true;
      lines.push(
        E("div", { class: "pdk-sub-error" }, [
          _("Expired on %s (%s)").format(date, relative(days, "day", "auto")),
        ]),
      );
    } else {
      lines.push(
        E("div", { class: days <= 7 ? "pdk-sub-warn" : "" }, [
          _("Valid until %s (%s)").format(date, relative(days, "day", "auto")),
        ]),
      );
    }
  } else if (info.traffic) {
    lines.push(E("div", {}, [_("No end date")]));
  }
  if (ended) {
    lines.push(
      E("div", { class: "pdk-sub-error" }, [
        _("The servers may refuse connections until the subscription is renewed"),
      ]),
    );
  }
  if (info.refill) {
    lines.push(
      E("div", {}, [
        _("Traffic resets %s").format(
          new Date(info.refill).toLocaleDateString(language, { dateStyle: "medium" }),
        ),
      ]),
    );
  }
  // a page of the provider shows its label only: the address of the subscription page is
  // often the address of the subscription itself, a secret
  const pages = [];
  if (info.support_url) {
    pages.push(
      E("a", { href: info.support_url, target: "_blank", rel: "noopener noreferrer" }, [
        _("Support") + " ↗",
      ]),
    );
  }
  if (info.web_page_url) {
    if (pages.length) {
      pages.push(" · ");
    }
    pages.push(
      E("a", { href: info.web_page_url, target: "_blank", rel: "noopener noreferrer" }, [
        _("Subscription page") + " ↗",
      ]),
    );
  }
  if (pages.length) {
    lines.push(E("div", {}, pages));
  }
  if (info.announce) {
    lines.push(
      E("div", { class: "pdk-sub-announce" }, [
        _("From the provider: %s").format(info.announce),
      ]),
    );
  }
  if (stale) {
    lines.push(E("div", { class: "cbi-value-description" }, [_("(data as of %s)").format(stale)]));
  }
  return E("div", { class: "pdk-sub-provider" }, lines);
}

// The list of a download, folded: a line a server with its name, its protocol and address,
// and why it cannot be used; its link folded under it.
function renderServers(preview) {
  const servers = preview.servers || [];
  const usable = servers.filter((server) => !server.reason).length;
  const others = (preview.attempts || [])
    .filter((attempt) => attempt.phase === "failed")
    .map((attempt) => wayOf(attempt.route) + ": " + tryReason(attempt));
  const summary = [
    _("%d servers, %d can be used").format(servers.length, usable),
    preview.took_ms >= 100
      ? _("%s in %s s").format(wayOf(preview.route), seconds(preview.took_ms))
      : wayOf(preview.route),
  ]
    .concat(others)
    .join(" · ");
  return E("details", { class: "pdk-sub-list", open: "" }, [
    E("summary", {}, [summary]),
    E(
      "ul",
      {},
      servers.map((server) =>
        E("li", { class: server.reason ? "pdk-sub-unusable" : "" }, [
          E("strong", {}, [server.name]),
          E("span", { class: "pdk-sub-endpoint" }, [
            " " + [server.scheme, server.address].filter(Boolean).join(", "),
          ]),
          server.reason
            ? E("div", { class: "pdk-sub-reason" }, [server.reason])
            : "",
          server.notes && server.notes.length
            ? E("div", { class: "pdk-sub-notes" }, [server.notes.join("; ")])
            : "",
          E("details", { class: "pdk-sub-link" }, [
            E("summary", {}, [_("Link")]),
            E("code", {}, [server.link]),
          ]),
        ]),
      ),
    ),
  ]);
}

// What a download for the page came to: the provider's data and the servers, or why not.
function renderPreview(preview) {
  if (preview.error) {
    return E("div", { class: "pdk-sub-error" }, [
      failureText(preview.error_code, preview.error_args, preview.error, preview.attempts),
    ]);
  }
  return E("div", {}, [providerBlock(preview.provider) || "", renderServers(preview)]);
}

// The groups of the form that take a subscription.
function groupsOf(name) {
  return uci
    .sections("podkop", "group")
    .filter((group) => L.toArray(group.subscription).includes(name))
    .map((group) => group[".name"]);
}

function createSubscriptionContent(section) {
  // the form is loaded again when a section is added or removed and at Save: the states are
  // asked anew then, their times counted by the clock of the router at that moment
  const load = section.load;
  section.load = function () {
    states = null;
    return load.apply(this, arguments);
  };

  let o = section.option(
    form.Value,
    "url",
    _("Subscription address"),
    _(
      "The address your provider gave for apps (often /sub/… or /api/sub/…). It is a secret: it is masked where podkop shows the settings",
    ),
  );
  o.password = true;
  o.rmempty = false;
  // LuCI would refuse an empty address as "Expecting: non-empty value": validate tells why
  o.optional = true;
  o.validate = function (section_id, value) {
    if (!value) {
      return _("The address is not set");
    }
    try {
      const address = new URL(value.trim());
      if (
        (address.protocol !== "https:" && address.protocol !== "http:") ||
        !address.hostname
      ) {
        return _("An address of HTTP or HTTPS is expected");
      }
    } catch (e) {
      return _("An address of HTTP or HTTPS is expected");
    }
    return true;
  };

  o = section.option(
    form.ListValue,
    "update_interval",
    _("Update interval"),
    _(
      "How often the router downloads the list again. A list whose servers only changed their names or order changes nothing",
    ),
  );
  o.value("1h", _("Every hour"));
  o.value("6h", _("Every 6 hours"));
  o.value("12h", _("Every 12 hours"));
  o.value("1d", _("Every day"));
  o.default = "12h";

  o = section.option(
    form.DummyValue,
    "_state",
    _("State"),
    _(
      "Servers changed: when a check first found the servers the router uses now. New names or order alone do not count",
    ),
  );
  o.rawhtml = true;
  o.cfgvalue = function (section_id) {
    const block = E("div", { class: "pdk-sub-state" }, [
      E("div", { class: "cbi-value-description" }, [_("Asking the router…")]),
    ]);
    subscriptionStates().then((list) => {
      const state = list.find((item) => item.name === section_id);
      const children = stateBlock(state).map((line) =>
        typeof line === "string" ? E("div", {}, [line]) : line,
      );
      if (state && state.provider) {
        // the data of the provider is of the last check that brought a list: after a failure it
        // is marked with its time; since the start, with the time of the list kept on flash
        const stale =
          state.error || !state.checked
            ? when(state.checked || state.changed, state.now)
            : null;
        children.push(providerBlock(state.provider, stale));
      }
      block.replaceChildren(...children);
    });
    return block;
  };

  // the groups that take the subscription, seen before it is deleted
  o = section.option(form.DummyValue, "_used", _("Groups"));
  o.rawhtml = true;
  o.cfgvalue = function (section_id) {
    const groups = groupsOf(section_id);
    return E("div", { class: "cbi-value-description" }, [
      groups.length ? groups.join(", ") : _("No group uses it yet"),
    ]);
  };

  // the list of the address of the form, saved or not: downloaded by the router, not taken;
  // a job of the router the page asks about every second, so a slow provider is waited for
  o = section.option(form.DummyValue, "_load", _("Servers"));
  o.rawhtml = true;
  o.cfgvalue = function (section_id) {
    const result = E("div", { class: "pdk-sub-result" }, []);
    let job = null;
    let timer = null;
    const cancel = E(
      "button",
      {
        class: "cbi-button cbi-button-negative",
        style: "display:none",
        click: (ev) => {
          ev.preventDefault();
          if (job) {
            main.PodkopShellMethods.subscriptionLoadCancel(job);
          }
        },
      },
      [_("Cancel")],
    );
    const show = (state) => {
      const attempts = state.attempts || [];
      if (state.state === "running") {
        result.replaceChildren(
          E("div", { class: "cbi-value-description" }, [
            _("The router downloads the list… %s s").format(seconds(state.elapsed_ms)),
          ]),
          E(
            "ul",
            { class: "pdk-sub-tries" },
            attempts.map((attempt) => E("li", {}, [attemptLine(attempt)])),
          ),
        );
        return;
      }
      result.replaceChildren(
        state.preview
          ? renderPreview(state.preview)
          : E("div", { class: "pdk-sub-error" }, [
              state.state === "canceled"
                ? failureText("canceled")
                : _("The router did not answer"),
            ]),
      );
    };
    const finish = () => {
      clearTimeout(timer);
      job = null;
      button.disabled = false;
      cancel.style.display = "none";
    };
    const poll = () => {
      main.PodkopShellMethods.subscriptionLoadState(job).then((response) => {
        if (!job) {
          return;
        }
        if (!response.success || !response.data) {
          result.replaceChildren(
            E("div", { class: "pdk-sub-error" }, [_("The router did not answer")]),
          );
          finish();
          return;
        }
        show(response.data);
        if (response.data.state === "running") {
          // a hidden tab asks less often
          timer = setTimeout(poll, document.hidden ? 5000 : 1000);
        } else {
          finish();
        }
      });
    };
    const button = E(
      "button",
      {
        class: "cbi-button cbi-button-action",
        click: (ev) => {
          ev.preventDefault();
          const address = (currentValue(section, section_id, "url") || "").trim();
          if (!address) {
            result.replaceChildren(
              E("div", { class: "pdk-sub-error" }, [_("The address is not set")]),
            );
            return;
          }
          button.disabled = true;
          result.replaceChildren(
            E("div", { class: "cbi-value-description" }, [
              _("The router downloads the list…"),
            ]),
          );
          main.PodkopShellMethods.subscriptionLoadStart(address).then((response) => {
            if (!response.success || !response.data) {
              result.replaceChildren(
                E("div", { class: "pdk-sub-error" }, [_("The router did not answer")]),
              );
              finish();
              return;
            }
            show(response.data);
            if (response.data.state === "running" && response.data.id) {
              job = response.data.id;
              cancel.style.display = "";
              timer = setTimeout(poll, 1000);
            } else {
              finish();
            }
          });
        },
      },
      [_("Load")],
    );
    return E("div", {}, [
      E("div", { class: "pdk-sub-load-actions" }, [button, cancel]),
      result,
    ]);
  };
}

const EntryPoint = {
  createSubscriptionContent,
};

return baseclass.extend(EntryPoint);
