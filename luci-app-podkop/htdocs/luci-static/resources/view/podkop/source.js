"use strict";
"require form";
"require baseclass";
"require uci";
"require ui";
"require tools.widgets as widgets";
"require view.podkop.main as main";
"require view.podkop.devices as devices";

// The tab Servers: the sources of servers ("config source"), a row each, edited in a window.
// A source is a subscription, links of servers, an outbound JSON or a network interface.

// a source of the settings as the page staged it, or null
function sourceOf(name) {
  const found = name ? uci.get("podkop", name) : null;
  return found && found[".type"] === "source" ? found : null;
}

// The value an option of a source has in its window now: what is being edited, else what is
// staged. Inside a window the options are those of the window's own form.
function currentValue(map, section_id, option) {
  const found = map.lookupOption(option, section_id);
  const value = found ? found[0].formvalue(found[1]) : null;
  return value != null ? value : uci.get("podkop", section_id, option);
}

// The state of the subscriptions as the router knows them, asked when the tab is drawn and
// when a window opens.
let states = [];
function refreshStates() {
  return main.PodkopShellMethods.subscriptionStatus().then((response) => {
    states =
      response.success && Array.isArray(response.data) ? response.data : [];
    return states;
  });
}

function stateOf(name) {
  return states.find((item) => item.name === name);
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
  const options = {
    day: "numeric",
    month: "short",
    hour: "2-digit",
    minute: "2-digit",
  };
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
    .replace(/\.(\d*?)0+(?=\s)/, (match, digits) =>
      digits ? "." + digits : "",
    );
}

function seconds(ms) {
  return (Math.round((ms || 0) / 100) / 10).toLocaleString(language);
}

function shortDate(text) {
  const time = new Date(text);
  return isNaN(time)
    ? text
    : time.toLocaleDateString(language, { dateStyle: "medium" });
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
      return _(
        "the provider redirects to plain HTTP, which goes directly only",
      );
    case "stalled":
      return _("the transfer stopped at %s").format(
        bytes(attempt.bytes || (+args[0] || 0) * 1024),
      );
    case "dns":
      return _("the name is not found in DNS");
    case "refused-connection":
      return _("the connection is refused");
    case "reset":
      return _("the connection is reset");
    case "tls":
      return _("the secure connection failed");
    case "cert":
      return _(
        "the certificate is not valid by the router's clock: check the clock",
      );
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
      return _("The provider could not be reached (%s)").format(
        reasons.join("; "),
      );
    }
    case "status-one": {
      // the status may be that of a CDN to the address of the one way that got it
      const reasons = (attempts || [])
        .filter(
          (attempt) => attempt.code !== "canceled" && attempt.code !== "status",
        )
        .map((attempt) => wayOf(attempt.route) + ": " + tryReason(attempt));
      return _(
        "HTTP %s came by one way only (%s); the other ways did not reach the provider (%s)",
      ).format(args[0], wayOf(args[1]), reasons.join("; "));
    }
    case "page":
      return _(
        "A web page came instead of the list: it may be the address of the provider's site, not of the subscription, or a page of the ISP",
      );
    case "refused":
      return _(
        "The provider refused the address (HTTP %s): it is wrong or out of date, or the subscription is blocked",
      ).format(args[0]);
    case "notfound":
      return _(
        "The provider has no subscription at this address (HTTP %s): the address is wrong, or the subscription was removed",
      ).format(args[0]);
    case "nocontent":
      return _(
        "The provider sent nothing (HTTP 204): the address is wrong, or the subscription was removed",
      );
    case "wait":
      return _(
        "The provider asks to wait (HTTP 429): the router tries again later",
      );
    case "server":
      return _(
        "The provider's server failed (HTTP %s): the router tries again later",
      ).format(args[0]);
    case "http":
      return _("The provider answered HTTP %s instead of the list").format(
        args[0],
      );
    case "hwid":
      return said(_("The provider did not accept this device (HWID)"));
    case "devices":
      return said(
        _(
          "The provider's limit of devices is reached: delete an old device in the provider's bot or account, then check again",
        ),
      );
    case "toobig":
      return _("The list is larger than %s MiB").format(args[0]);
    case "empty":
      return _("The provider sent an empty list");
    case "nolinks":
      return _("The answer of the provider has no links of servers");
    case "json":
      return _(
        "The provider sent a configuration in JSON (sing-box or Xray): podkop reads only a list of links so far",
      );
    case "clash":
      return _(
        "The provider sent a configuration of Clash (YAML): podkop reads only a list of links so far",
      );
    case "placeholder":
      return _("The provider sent notes instead of servers: %s").format(
        args[0],
      );
    case "address":
      return _("An address of HTTP or HTTPS is expected");
    case "noway":
      return _("There is no way to the provider to try");
    case "fault":
      return _("The download stopped on a fault of podkop: see the log");
    case "notrunning":
      return _("podkop is not running: start it to load the list");
    case "nojob":
      return _(
        "The download is lost: podkop restarted, or it ended long ago. Press Load again",
      );
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
      progress = _("waiting for the provider: %s s").format(
        seconds(attempt.ms),
      );
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
  return wayOf(attempt.route) + ": " + progress;
}

// What the router knows of a subscription, a line a fact: its servers, the last check and its
// way, when its servers changed, the next check; a failure with the list kept.
function stateLines(state) {
  if (!state) {
    return [
      _("Not downloaded yet: the router downloads the list after Save & Apply"),
    ];
  }
  const now = state.now;
  const lines = [];
  if (state.changed) {
    lines.push(
      _("Servers: %d, usable: %d").format(state.servers, state.usable),
    );
  }
  if (state.busy) {
    lines.push(_("Checking now…"));
  }
  const failed = !!state.error;
  if (failed) {
    lines.push(
      lineWith(
        _("Last check: %s, failed"),
        timeOf(state.attempted || state.next, now),
      ),
    );
    lines.push(
      failureText(
        state.error_code,
        state.error_args,
        state.error,
        state.attempts,
      ),
    );
    if (state.changed) {
      lines.push(
        lineWith(
          _("The list from %s stays in use"),
          timeOf(state.changed, now),
        ),
      );
    } else {
      lines.push(_("No list yet: the rows of this source name no server"));
    }
  } else if (state.checked) {
    const took =
      state.took_ms >= 100
        ? ", " + _("%s s").format(seconds(state.took_ms))
        : "";
    lines.push(
      lineWith(
        _("Last check: %s, %s"),
        timeOf(state.checked, now),
        wayOf(state.route) + took,
      ),
    );
  } else if (state.changed) {
    lines.push(_("Last check: none since podkop started"));
  } else {
    lines.push(_("The list is not downloaded yet"));
  }
  if (state.changed) {
    lines.push(lineWith(_("Servers changed: %s"), timeOf(state.changed, now)));
  }
  const changes = state.changes;
  if (changes) {
    lines.push(
      _(
        "What changed: renamed %d, other server under the name %d, removed %d, added %d",
      ).format(
        changes.renamed,
        changes.changed,
        changes.removed,
        changes.added,
      ),
    );
    if (changes.fields && changes.fields.length) {
      lines.push(
        _("Options that changed: %s").format(changes.fields.join(", ")),
      );
    }
  }
  if (state.next && !state.busy) {
    lines.push(
      lineWith(
        failed ? _("Next try: %s") : _("Next check: %s"),
        timeOf(state.next, now),
      ),
    );
  }
  return lines;
}

// What the provider told of a subscription: its title, the traffic, the end, the reset, its
// pages, its notice. stale: the time of the list the data came with, when it is not of a
// fresh check.
function providerLines(info, stale) {
  if (!info) {
    return [];
  }
  const lines = [E("strong", {}, [_("From the provider")])];
  if (info.title) {
    lines.push(_("Name at the provider: %s").format(info.title));
  }
  let ended = false;
  if (info.traffic) {
    const used = (info.upload || 0) + (info.download || 0);
    if (info.total) {
      const share = Math.min(100, Math.round((used / info.total) * 100));
      const usedUp = used >= info.total;
      ended = ended || usedUp;
      lines.push(
        (usedUp
          ? _("Traffic: %s of %s, used up")
          : _("Traffic: %s of %s")
        ).format(bytes(used), bytes(info.total)),
      );
      lines.push(
        E(
          "div",
          {
            class: "cbi-progressbar",
            title: "%s / %s (%d%%)".format(
              bytes(used),
              bytes(info.total),
              share,
            ),
          },
          E("div", { style: "width:%d%%".format(share) }),
        ),
      );
    } else {
      lines.push(_("Traffic: %s, no limit").format(bytes(used)));
    }
  }
  if (info.expire) {
    const end = new Date(info.expire);
    const days = calendarDays(end, new Date());
    if (end <= new Date()) {
      ended = true;
      lines.push(
        _("Expired on %s (%s)").format(
          shortDate(info.expire),
          relative(days, "day", "auto"),
        ),
      );
    } else {
      lines.push(
        _("Valid until %s (%s)").format(
          shortDate(info.expire),
          relative(days, "day", "auto"),
        ),
      );
    }
  } else if (info.traffic) {
    lines.push(_("No end date"));
  }
  if (ended) {
    lines.push(
      _("The servers may refuse connections until the subscription is renewed"),
    );
  }
  if (info.refill) {
    lines.push(_("Traffic resets %s").format(shortDate(info.refill)));
  }
  if (info.update_hours) {
    lines.push(
      _("The provider advises to update every %d h").format(info.update_hours),
    );
  }
  // a page of the provider shows its label only: the address of the subscription page is
  // often the address of the subscription itself, a secret
  const pages = [];
  if (info.support_url) {
    pages.push(
      E(
        "a",
        {
          href: info.support_url,
          target: "_blank",
          rel: "noopener noreferrer",
        },
        [_("Support")],
      ),
    );
  }
  if (info.web_page_url) {
    if (pages.length) {
      pages.push(" · ");
    }
    pages.push(
      E(
        "a",
        {
          href: info.web_page_url,
          target: "_blank",
          rel: "noopener noreferrer",
        },
        [_("Subscription page")],
      ),
    );
  }
  if (pages.length) {
    lines.push(E("div", {}, pages));
  }
  if (info.announce) {
    lines.push(
      E("div", { style: "white-space:pre-line" }, [
        _("From the provider: %s").format(info.announce),
      ]),
    );
  }
  if (stale) {
    lines.push(
      E("div", { class: "cbi-value-description" }, [
        _("(data as of %s)").format(stale),
      ]),
    );
  }
  return lines;
}

// lines as a block: a string a line of its own
function block(lines) {
  return E(
    "div",
    {},
    lines.map((line) =>
      typeof line === "string" ? E("div", {}, [line]) : line,
    ),
  );
}

// The servers of a download: a table of their names, protocols and addresses, and why one
// cannot be used.
function serversTable(preview) {
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
  return E("div", {}, [
    E("div", {}, [summary]),
    E("table", { class: "table" }, [
      E("tr", { class: "tr table-titles" }, [
        E("th", { class: "th" }, [_("Server")]),
        E("th", { class: "th" }, [_("Protocol")]),
        E("th", { class: "th" }, [_("Address")]),
        E("th", { class: "th" }, [_("Note")]),
      ]),
      ...servers.map((server) =>
        E("tr", { class: "tr" }, [
          E("td", { class: "td", "data-title": _("Server") }, [
            server.name || "",
          ]),
          E("td", { class: "td", "data-title": _("Protocol") }, [
            server.scheme || "",
          ]),
          E("td", { class: "td", "data-title": _("Address") }, [
            server.address || "",
          ]),
          E("td", { class: "td", "data-title": _("Note") }, [
            [server.reason ? _("cannot be used: %s").format(server.reason) : ""]
              .concat(server.notes || [])
              .filter(Boolean)
              .join("; "),
          ]),
        ]),
      ),
    ]),
  ]);
}

// What a download for the window came to: the provider's data and the servers, or why not.
function previewBlock(preview) {
  if (preview.error) {
    return block([
      failureText(
        preview.error_code,
        preview.error_args,
        preview.error,
        preview.attempts,
      ),
    ]);
  }
  return E("div", {}, [
    block(providerLines(preview.provider)),
    serversTable(preview),
  ]);
}

// The list of the address of the window, saved or not: downloaded by the router, not taken; a
// job of the router the page asks about every second, so a slow provider is waited for. The
// promise ends with the job: the button of LuCI waits with it.
function loadPreview(address, result) {
  return new Promise((resolve) => {
    let job = null;
    const cancel = E(
      "button",
      {
        class: "cbi-button cbi-button-negative",
        click: (ev) => {
          ev.preventDefault();
          if (job) {
            main.PodkopShellMethods.subscriptionLoadCancel(job);
          }
        },
      },
      [_("Cancel")],
    );
    const failed = (text) => {
      result.replaceChildren(block([text]));
      resolve();
    };
    const show = (state) => {
      if (state.state === "running") {
        result.replaceChildren(
          block([
            _("The router downloads the list… %s s").format(
              seconds(state.elapsed_ms),
            ),
            ...(state.attempts || []).map(attemptLine),
          ]),
          cancel,
        );
        return false;
      }
      result.replaceChildren(
        state.preview
          ? previewBlock(state.preview)
          : block([
              state.state === "canceled"
                ? failureText("canceled")
                : _("The router did not answer"),
            ]),
      );
      return true;
    };
    const poll = () => {
      main.PodkopShellMethods.subscriptionLoadState(job).then((response) => {
        if (!response.success || !response.data) {
          return failed(_("The router did not answer"));
        }
        if (show(response.data)) {
          return resolve();
        }
        // a hidden tab asks less often
        setTimeout(poll, document.hidden ? 5000 : 1000);
      });
    };
    result.replaceChildren(block([_("The router downloads the list…")]));
    main.PodkopShellMethods.subscriptionLoadStart(address).then((response) => {
      if (!response.success || !response.data) {
        return failed(_("The router did not answer"));
      }
      if (show(response.data) || !response.data.id) {
        return resolve();
      }
      job = response.data.id;
      setTimeout(poll, 1000);
    });
  });
}

// What a source is, for the column Type
function typeText(item) {
  switch (main.sourceKind(item)) {
    case "subscription":
      return _("Subscription");
    case "links": {
      const count = main.sourceLinks(item).length;
      return count === 1
        ? _("Server link")
        : _("Server links: %d").format(count);
    }
    case "json":
      return _("Outbound JSON");
    case "interface":
      return _("Interface");
  }
  return _("Not filled");
}

// How a source is, for the column State
function stateText(item) {
  const kind = main.sourceKind(item);
  if (!main.sourceFilled(item)) {
    return [_("Waiting for a link")];
  }
  if (kind === "subscription") {
    const state = stateOf(item[".name"]);
    if (!state) {
      return [_("Downloaded after Save & Apply")];
    }
    const lines = [
      state.changed ? _("Servers: %d").format(state.servers) : _("No list yet"),
    ];
    if (state.error) {
      lines.push(_("The last check failed"));
    }
    const info = state.provider;
    if (info) {
      const facts = [];
      if (info.traffic && info.total) {
        facts.push(
          _("%s of %s").format(
            bytes((info.upload || 0) + (info.download || 0)),
            bytes(info.total),
          ),
        );
      }
      if (info.expire) {
        facts.push(_("until %s").format(shortDate(info.expire)));
      }
      if (facts.length) {
        lines.push(facts.join(", "));
      }
    }
    return lines;
  }
  if (kind === "links") {
    const links = main.sourceLinks(item);
    return [
      links.length === 1
        ? main.linkHost(links[0]) || _("Ready")
        : _("Servers: %d").format(links.length),
    ];
  }
  if (kind === "interface") {
    return [
      (item.interface || _("Main route")) +
        (item.routing_mark
          ? ", " + _("mark %s").format(item.routing_mark)
          : ""),
    ];
  }
  return [_("Ready")];
}

// The rules whose rows name a source, for the message when it is deleted
function rulesUsing(name) {
  const rules = new Set();
  uci.sections("podkop", "member").forEach((row) => {
    if (row.source === name || row.via === name) {
      const rule = uci.get("podkop", row.section);
      if (rule) {
        rules.add(String(rule.label || "").trim() || row.section);
      }
    }
  });
  return [...rules];
}

// A source deleted: the rows of the rules that name it stay, marked as deleted in their rule
function sourceRemoved(name) {
  const used = rulesUsing(name);
  if (used.length) {
    ui.addNotification(
      null,
      E("p", {}, [
        _(
          "The deleted source was used by the rules: %s. Their rows show it as deleted: choose another source there",
        ).format(used.join(", ")),
      ]),
      "warning",
    );
  }
}

// A source a rule names that is not filled yet (src1 of a fresh install): Add opens it
function sourceWaiting() {
  const named = new Set(
    uci.sections("podkop", "member").map((row) => row.source),
  );
  const waiting = uci
    .sections("podkop", "source")
    .find((item) => named.has(item[".name"]) && !main.sourceFilled(item));
  return waiting ? waiting[".name"] : null;
}

// The options that hold the values of one type are kept when the type is "detect": the text
// pasted decides then (option _paste), and it writes them itself.
function keptWhilePasting(option) {
  option.remove = function (section_id) {
    if (currentValue(this.map, section_id, "type") === "auto") {
      return;
    }
    return uci.unset("podkop", section_id, this.option);
  };
}

// the options a pasted text replaces
const VALUE_OPTIONS = [
  "url",
  "update_interval",
  "link",
  "udp_over_tcp",
  "outbound_json",
  "interface",
  "routing_mark",
  "domain_resolver_enabled",
  "domain_resolver_dns_type",
  "domain_resolver_dns_server",
];

function createSourceContent(section) {
  section.modaltitle = function (section_id) {
    const item = sourceOf(section_id);
    return _("Servers") + " » " + (item ? main.sourceLabel(item) : section_id);
  };
  // the states of the subscriptions are asked anew whenever the list is drawn
  section.load = function () {
    return Promise.all([
      refreshStates().catch(() => []),
      form.GridSection.prototype.load.apply(this, arguments),
    ]).then((results) => results[1]);
  };
  section.renderSectionPlaceholder = function () {
    return E("em", {}, [
      _("Nothing yet: press Add and paste a subscription or a link"),
    ]);
  };

  // the columns of the list
  let o = section.option(form.DummyValue, "_name", _("Name"));
  o.modalonly = false;
  o.textvalue = function (section_id) {
    const item = sourceOf(section_id);
    return E("strong", {}, [item ? main.sourceLabel(item) : section_id]);
  };

  o = section.option(form.DummyValue, "_type", _("Type"));
  o.modalonly = false;
  o.textvalue = function (section_id) {
    return E("span", {}, [typeText(sourceOf(section_id) || {})]);
  };

  o = section.option(form.DummyValue, "_state", _("State"));
  o.modalonly = false;
  o.textvalue = function (section_id) {
    const item = sourceOf(section_id);
    return block(item ? stateText(item) : []);
  };

  // the window
  o = section.option(
    form.ListValue,
    "type",
    _("Type"),
    _("Detect: the type follows the pasted text"),
  );
  o.modalonly = true;
  o.value("auto", _("Detect from the pasted text"));
  o.value("subscription", _("Subscription"));
  o.value("links", _("Server links"));
  o.value("json", _("Outbound JSON"));
  o.value("interface", _("Interface"));
  o.rmempty = false;
  o.load = function (section_id) {
    const type = uci.get("podkop", section_id, "type");
    return main.SOURCE_KINDS.includes(type) ? type : "auto";
  };
  o.write = function (section_id, value) {
    if (value === "auto") {
      return uci.unset("podkop", section_id, "type");
    }
    return uci.set("podkop", section_id, "type", value);
  };

  // the pasted text: its type is recognized, and it goes to the field of that type
  o = section.option(
    form.TextValue,
    "_paste",
    _("Link or subscription"),
    _(
      "A subscription address, links of servers (one per line) or an outbound JSON",
    ),
  );
  o.modalonly = true;
  o.depends("type", "auto");
  o.rows = 4;
  o.wrap = "soft";
  o.placeholder = "https://…  vless://…  hy2://…  {…}";
  o.load = function () {
    return "";
  };
  o.validate = function (section_id, value) {
    const found = main.detectPasted(value);
    if (found.kind === "error") {
      return found.note ? found.title + ": " + found.note : found.title;
    }
    return true;
  };
  // A text pasted is recognized at once: the type and its field are filled, so the options of
  // that type show before Save. A text typed is left as it is until Save (written below): the
  // window must not change under the pointer that leaves the field for the button Save.
  o.renderWidget = function (section_id, option_index, cfgvalue) {
    const node = form.TextValue.prototype.renderWidget.call(
      this,
      section_id,
      option_index,
      cfgvalue,
    );
    const area = node.querySelector ? node.querySelector("textarea") : null;
    if (area) {
      area.addEventListener("paste", () =>
        setTimeout(() => this.recognize(section_id), 0),
      );
    }
    return node;
  };
  o.recognize = function (section_id) {
    const found = main.detectPasted(this.formvalue(section_id));
    if (!["subscription", "links", "json"].includes(found.kind)) {
      return;
    }
    const map = this.map;
    const widget = (option) => {
      const located = map.lookupOption(option, section_id);
      return located ? located[0].getUIElement(located[1]) : null;
    };
    const fields = {
      subscription: "url",
      links: "link",
      json: "outbound_json",
    };
    const values = {
      subscription: found.url,
      links: found.links,
      json: found.json,
    };
    const target = widget(fields[found.kind]);
    const type = widget("type");
    const pasted = this.getUIElement(section_id);
    if (!target || !type || !pasted) {
      return;
    }
    target.setValue(values[found.kind]);
    type.setValue(found.kind);
    pasted.setValue("");
    map.checkDepends();
    const frame = map.findElement("id", "cbi-podkop-" + section_id + "-type");
    const note = frame ? frame.querySelector(".cbi-value-description") : null;
    if (note) {
      note.textContent = _("Recognized: %s").format(
        [found.title, found.note].filter(Boolean).join(". "),
      );
    }
  };
  // a text that was not moved to its field is written here at Save
  o.write = function (section_id, value) {
    const found = main.detectPasted(value);
    VALUE_OPTIONS.forEach((option) => uci.unset("podkop", section_id, option));
    switch (found.kind) {
      case "subscription":
        uci.set("podkop", section_id, "type", "subscription");
        uci.set("podkop", section_id, "url", found.url);
        break;
      case "links":
        uci.set("podkop", section_id, "type", "links");
        uci.set("podkop", section_id, "link", found.links);
        break;
      case "json":
        uci.set("podkop", section_id, "type", "json");
        uci.set("podkop", section_id, "outbound_json", found.json);
        break;
    }
  };
  // "detect" with nothing pasted empties the source
  o.remove = function (section_id) {
    if (currentValue(this.map, section_id, "type") !== "auto") {
      return;
    }
    uci.unset("podkop", section_id, "type");
    VALUE_OPTIONS.forEach((option) => uci.unset("podkop", section_id, option));
  };

  // subscription
  o = section.option(
    form.Value,
    "url",
    _("Subscription address"),
    _(
      "The address your provider gave for apps (often /sub/… or /api/sub/…). It is a secret: podkop masks it where it shows the settings",
    ),
  );
  o.modalonly = true;
  o.depends("type", "subscription");
  o.password = true;
  o.rmempty = false;
  // LuCI would refuse an empty address as "Expecting: non-empty value": validate tells why
  o.optional = true;
  o.validate = function (section_id, value) {
    if (!value) {
      return _("The address is not set");
    }
    const unwrapped = main.unwrapSubscription(value);
    const text = unwrapped ? unwrapped.url : value.trim();
    try {
      const address = new URL(text);
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
  // the link of an app that adds the subscription (happ://add/…) is kept as its address
  o.write = function (section_id, value) {
    const unwrapped = main.unwrapSubscription(value);
    return uci.set(
      "podkop",
      section_id,
      "url",
      unwrapped ? unwrapped.url : value.trim(),
    );
  };
  keptWhilePasting(o);

  o = section.option(
    form.ListValue,
    "update_interval",
    _("Update interval"),
    _("Automatically: as the provider advises, otherwise once a day"),
  );
  o.modalonly = true;
  o.depends("type", "subscription");
  o.default = "auto";
  o.renderWidget = function (section_id, option_index, cfgvalue) {
    this.keylist = [];
    this.vallist = [];
    this.value("auto", _("Automatically"));
    this.value("20m", _("Every 20 minutes"));
    this.value("1h", _("Every hour"));
    this.value("3h", _("Every 3 hours"));
    this.value("6h", _("Every 6 hours"));
    this.value("9h", _("Every 9 hours"));
    this.value("12h", _("Every 12 hours"));
    this.value("1d", _("Every day"));
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

  o = section.option(
    form.DummyValue,
    "_status",
    _("State"),
    _(
      "Servers changed: when a check last found other servers or names. A new order alone does not count. The router takes the new servers without a restart",
    ),
  );
  o.modalonly = true;
  o.depends("type", "subscription");
  o.rawhtml = true;
  // asked anew when a window opens (its form has a parent); the list asks for every source
  o.load = function () {
    return this.map.parent
      ? refreshStates().catch(() => states)
      : Promise.resolve();
  };
  o.cfgvalue = function (section_id) {
    if (arguments.length > 1) {
      return null;
    }
    const state = stateOf(section_id);
    const lines = stateLines(state);
    if (state && state.provider) {
      // the data of the provider is of the last check that brought a list: after a failure it
      // is marked with its time; since the start, with the time of the list kept on flash
      const stale =
        state.error || !state.checked
          ? when(state.checked || state.changed, state.now)
          : null;
      lines.push(...providerLines(state.provider, stale));
    }
    return block(lines);
  };
  o.parse = function () {
    return Promise.resolve();
  };

  o = section.option(
    form.Button,
    "_load",
    _("Servers"),
    _(
      "The router downloads the list of the address above to show it here, first directly, then through the working servers. It is taken after Save & Apply",
    ),
  );
  o.modalonly = true;
  o.depends("type", "subscription");
  o.inputtitle = _("Load");
  o.inputstyle = "action";
  o.onclick = function (ev, section_id) {
    const result = document.getElementById("pdk-preview-" + section_id);
    if (!result) {
      return;
    }
    const value = String(
      currentValue(this.map, section_id, "url") || "",
    ).trim();
    const unwrapped = main.unwrapSubscription(value);
    const address = unwrapped ? unwrapped.url : value;
    if (!address) {
      result.replaceChildren(block([_("The address is not set")]));
      return;
    }
    return loadPreview(address, result);
  };

  o = section.option(form.DummyValue, "_preview");
  o.modalonly = true;
  o.depends("type", "subscription");
  o.rawhtml = true;
  o.cfgvalue = function (section_id) {
    if (arguments.length > 1) {
      return null;
    }
    return E("div", { id: "pdk-preview-" + section_id }, []);
  };
  o.parse = function () {
    return Promise.resolve();
  };

  // links
  o = section.option(
    form.DynamicList,
    "link",
    _("Server links"),
    _(
      "Share links: vless, ss, trojan, socks, http(s), hysteria2, tuic, and vmess, anytls, hysteria, naive where the engine has them",
    ),
  );
  o.modalonly = true;
  o.depends("type", "links");
  o.placeholder = "vless://…";
  o.validate = function (section_id, value) {
    if (!value || value.length === 0) {
      return true;
    }
    const validation = main.validateProxyUrl(value);
    return validation.valid ? true : validation.message;
  };
  keptWhilePasting(o);

  o = section.option(
    form.Flag,
    "udp_over_tcp",
    _("UDP over TCP"),
    _("Applicable for SOCKS and Shadowsocks proxy"),
  );
  o.modalonly = true;
  o.depends("type", "links");
  o.default = "0";

  // outbound JSON
  o = section.option(
    form.TextValue,
    "outbound_json",
    _("Outbound Configuration"),
    _("Enter complete outbound configuration in JSON format"),
  );
  o.modalonly = true;
  o.depends("type", "json");
  o.rows = 10;
  o.validate = function (section_id, value) {
    if (!value || value.length === 0) {
      return true;
    }
    const found = main.detectPasted(value);
    if (found.kind === "json") {
      return true;
    }
    if (found.kind === "error") {
      return found.note ? found.title + ": " + found.note : found.title;
    }
    return _('An outbound of sing-box is expected: {"type": "vless", …}');
  };
  keptWhilePasting(o);

  // interface
  o = section.option(
    widgets.DeviceSelect,
    "interface",
    _("Network Interface"),
    _("A tunnel, a modem or a second WAN. Empty: the main route"),
  );
  o.modalonly = true;
  o.depends("type", "interface");
  devices.forRole(o, "out");

  o = section.option(
    form.Value,
    "routing_mark",
    _("Routing mark"),
    _("The mark of the connections for mwan3 or pbr. Empty: no mark"),
  );
  o.modalonly = true;
  o.depends("type", "interface");
  o.placeholder = "0x10000";
  o.validate = function (section_id, value) {
    return main.validateRoutingMark(value) || true;
  };

  o = section.option(
    form.Flag,
    "domain_resolver_enabled",
    _("Domain Resolver"),
    _(
      "The real IP of a site is resolved by a DNS server reached through this interface",
    ),
  );
  o.modalonly = true;
  o.depends("type", "interface");
  o.default = "0";

  o = section.option(
    form.ListValue,
    "domain_resolver_dns_type",
    _("DNS Protocol Type"),
    _("Select the DNS protocol type for the domain resolver"),
  );
  o.modalonly = true;
  o.value("udp", _("UDP (Unprotected DNS)"));
  o.value("dot", _("DNS over TLS (DoT)"));
  o.value("doh", _("DNS over HTTPS (DoH)"));
  o.default = "udp";
  o.depends("domain_resolver_enabled", "1");

  o = section.option(
    form.Value,
    "domain_resolver_dns_server",
    _("DNS Server"),
    _("Select or enter DNS server address"),
  );
  o.modalonly = true;
  Object.entries(main.DNS_SERVER_OPTIONS).forEach(([key, label]) => {
    o.value(key, _(label));
  });
  o.default = "1.1.1.1";
  o.rmempty = false;
  o.depends("domain_resolver_enabled", "1");
  o.validate = function (section_id, value) {
    const validation = main.validateDNS(value);
    return validation.valid ? true : validation.message;
  };

  // the name it is shown by
  o = section.option(
    form.Value,
    "label",
    _("Name"),
    _("Empty: the name is made from the address, the link or the interface"),
  );
  o.modalonly = true;
  o.renderWidget = function (section_id, option_index, cfgvalue) {
    const item = sourceOf(section_id);
    this.placeholder = item ? main.sourceAutoLabel(item) : section_id;
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
}

const EntryPoint = {
  createSourceContent,
  sourceRemoved,
  sourceWaiting,
};

return baseclass.extend(EntryPoint);
