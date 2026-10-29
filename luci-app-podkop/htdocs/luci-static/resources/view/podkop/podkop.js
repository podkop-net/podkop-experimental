"use strict";
"require view";
"require form";
"require baseclass";
"require network";
"require uci";
"require ui";
"require view.podkop.main as main";

// Settings content
"require view.podkop.settings as settings";

// Servers (sources) and rules content
"require view.podkop.source as source";
"require view.podkop.rules as rules";

// Dashboard content
"require view.podkop.dashboard as dashboard";

// Diagnostic content
"require view.podkop.diagnostic as diagnostic";

// The sources, the rules and their rows are sections of one file, and its names are one
// namespace: a source named as a rule would merge into it. A new source or rule gets the first
// name of its kind that no section has (src1, src2…, rule1, rule2…); direct and block name
// where a row goes without a server and are never given.
function freeName(prefix) {
  const deleted =
    (uci.state && uci.state.deletes && uci.state.deletes.podkop) || {};
  for (let index = 1; ; index++) {
    const name = prefix + index;
    if (
      !main.RESERVED_NAMES.includes(name) &&
      !uci.get("podkop", name) &&
      !deleted[name]
    ) {
      return name;
    }
  }
}

// two values of a field alike: a list or one value
function sameValue(a, b) {
  const list = (value) =>
    Array.isArray(value)
      ? value.map(String)
      : value == null || value === ""
        ? []
        : [String(value)];
  return JSON.stringify(list(a)) === JSON.stringify(list(b));
}

// The form is staged as LuCI stages a section added or removed (the change is saved to the
// router's staging area, and the form drawn again when asked), but only the fields the user
// changed: a field that shows its default, or a field hidden now, is left to Save, so that
// opening a window changes nothing. A field that does not pass its check does not stop it: it
// is told at Save. A list of rows has only the fields edited in its rows (the switch of a
// rule); the dashboard and the diagnostics hold no settings.
function stage(map, render) {
  map.checkDepends();
  const tasks = [];
  map.children
    .filter(
      (section) =>
        section.sectiontype !== "diagnostic" &&
        section.sectiontype !== "dashboard",
    )
    .forEach((section) => {
      const grid = section instanceof form.GridSection;
      const options = section.children.filter(
        (option) => !grid || (option.editable && !option.modalonly),
      );
      section.cfgsections().forEach((section_id) => {
        options.forEach((option) => {
          if (!option.isActive(section_id)) {
            return;
          }
          const saved = option.cfgvalue(section_id);
          const shown = option.formvalue(section_id);
          if (!sameValue(shown, saved != null ? saved : option.default)) {
            tasks.push(
              Promise.resolve(option.parse(section_id)).catch(() => {}),
            );
          }
        });
      });
    });
  return Promise.all(tasks)
    .then(() => map.data.save())
    .then(() => (render ? map.load().then(() => map.renderContents()) : null));
}

// A list of sources or of rules, each edited in a window of LuCI. The form is staged before a
// window opens: a window that saves draws the form again from the staged settings, so what
// was changed on the other tabs stays. A window that staged its own changes (the rows of a
// rule are added and removed that way) and is dismissed draws the form again too.
function gridSection(grid, prefix, hooks) {
  const map = grid.map;
  grid.handleAdd = function () {
    return stage(map).then(() => {
      const name = freeName(prefix);
      map.data.add("podkop", this.sectiontype, name);
      if (hooks.added) {
        hooks.added(name);
      }
      map.addedSection = name;
      return form.GridSection.prototype.renderMoreOptionsModal.call(this, name);
    });
  };
  grid.handleRemove = function (section_id) {
    if (hooks.removed) {
      hooks.removed(section_id);
    }
    map.data.remove("podkop", section_id);
    return stage(map, true);
  };
  grid.renderMoreOptionsModal = function (section_id, ev) {
    if (this.getActiveModalMap()) {
      return form.GridSection.prototype.renderMoreOptionsModal.call(
        this,
        section_id,
        ev,
      );
    }
    return stage(map).then(() =>
      form.GridSection.prototype.renderMoreOptionsModal.call(
        this,
        section_id,
        ev,
      ),
    );
  };
  grid.handleModalCancel = function (modalMap, ev, isSaving) {
    const stacked = !!this.getPreviousModalMap();
    const added = !isSaving && !stacked ? map.addedSection : null;
    const staged = !isSaving && !stacked && modalMap && modalMap.pdkStaged;
    return Promise.resolve(
      form.GridSection.prototype.handleModalCancel.call(
        this,
        modalMap,
        ev,
        isSaving,
      ),
    ).then(() => {
      if (added != null && hooks.removed) {
        hooks.removed(added);
      }
      if (staged) {
        return stage(map, true);
      }
    });
  };
}

// The values of the file as the page staged them
function configModel() {
  const of = (type) => uci.sections("podkop", type);
  return {
    rules: of("section"),
    sources: of("source"),
    members: of("member"),
  };
}

function ruleTitle(name) {
  const rule = uci.get("podkop", name);
  return (rule && String(rule.label || "").trim()) || name;
}

const EntryPoint = {
  async render() {
    main.injectGlobalStyles();

    // Options of features the installed sing-box does not have are not created
    const singBoxFeatures = await main.CustomPodkopMethods.getSingBoxFeatures();

    const podkopMap = new form.Map(
      "podkop",
      _("Podkop Settings"),
      _("Configuration for Podkop service"),
    );
    // Enable tab views
    podkopMap.tabbed = true;

    // Servers tab: subscriptions, links of servers, outbound JSON, interfaces
    const sourcesSection = podkopMap.section(
      form.GridSection,
      "source",
      _("Servers"),
      _(
        "Subscriptions, links of servers and interfaces. The rules take their servers from here.",
      ),
    );
    sourcesSection.hidetitle = true;
    sourcesSection.anonymous = true;
    sourcesSection.addremove = true;
    source.createSourceContent(sourcesSection, singBoxFeatures);
    gridSection(sourcesSection, "src", {
      removed: (name) => source.sourceRemoved(name),
    });

    // Rules tab: which sites go through which servers
    const rulesSection = podkopMap.section(
      form.GridSection,
      "section",
      _("Rules"),
      _(
        "Which sites go through which servers. When a site is in several rules, the upper one works. Drag ☰ to change the order. The server in use is shown on the dashboard.",
      ),
    );
    rulesSection.hidetitle = true;
    rulesSection.anonymous = true;
    rulesSection.addremove = true;
    rulesSection.sortable = true;
    rules.createRulesContent(rulesSection, singBoxFeatures);
    gridSection(rulesSection, "rule", {
      added: (name) => rules.ruleAdded(name),
      removed: (name) => rules.ruleRemoved(name),
    });

    // Settings tab
    const settingsSection = podkopMap.section(
      form.TypedSection,
      "settings",
      _("Settings"),
    );
    settingsSection.hidetitle = true;
    settingsSection.anonymous = true;
    settingsSection.addremove = false;
    // Make it named [ config settings 'settings' ]
    settingsSection.cfgsections = function () {
      return ["settings"];
    };

    // Render settings content
    settings.createSettingsContent(settingsSection, singBoxFeatures);

    // Diagnostic tab
    const diagnosticSection = podkopMap.section(
      form.TypedSection,
      "diagnostic",
      _("Diagnostics"),
    );
    diagnosticSection.hidetitle = true;
    diagnosticSection.anonymous = true;
    diagnosticSection.addremove = false;
    diagnosticSection.cfgsections = function () {
      return ["diagnostic"];
    };

    // Render diagnostic content
    diagnostic.createDiagnosticContent(diagnosticSection);

    // Dashboard tab
    const dashboardSection = podkopMap.section(
      form.TypedSection,
      "dashboard",
      _("Dashboard"),
    );
    dashboardSection.hidetitle = true;
    dashboardSection.anonymous = true;
    dashboardSection.addremove = false;
    dashboardSection.cfgsections = function () {
      return ["dashboard"];
    };

    // Render dashboard content
    dashboard.createDashboardContent(dashboardSection);

    // The window of a source or a rule, from its tab
    const openWindow = (tab, grid, name) => {
      const link = document.querySelector(
        'ul.cbi-tabmenu li[data-tab="' + tab + '"] a',
      );
      if (link) {
        link.click();
      }
      return grid.renderMoreOptionsModal(name);
    };

    // A save by the user first checks what the backend would refuse the whole configuration
    // for: the rows of the rules that connect through a source that cannot be used, then
    // the proxy links of the sources, which the router's engine is asked about. Either keeps
    // the settings from being saved, with the window to fix it. The silent saves of LuCI
    // (a section added or removed, a window saved) are left alone.
    const save = podkopMap.save;
    podkopMap.save = function (cb, silent) {
      if (silent) {
        return save.call(this, cb, silent);
      }
      // what the form holds now, the switches of the rules in the list included
      return Promise.resolve(this.parse())
        .catch(() => {})
        .then(() => {
          const model = configModel();
          const rows = main.ruleRowProblems(
            model.rules,
            model.sources,
            model.members,
          );
          if (rows.length) {
            main.showSaveProblems(
              _("Some rows of the rules cannot be used"),
              _(
                "The settings are not saved. These rows connect through a source that cannot be used:",
              ),
              rows.map((row) => ({
                heading:
                  ruleTitle(row.rule) +
                  " · " +
                  (row.role === "fallback" ? _("Fallback") : _("Servers")) +
                  " · " +
                  row.index,
                lines: [row.error],
                show: () => openWindow("section", rulesSection, row.rule),
              })),
            );
            return Promise.reject(new Error("rows of the rules refused"));
          }
          return main.checkLinksBeforeSave(model.sources).then((problems) => {
            if (problems.length) {
              main.showLinkProblems(problems, (name) =>
                openWindow("source", sourcesSection, name),
              );
              return Promise.reject(
                new Error("proxy links refused by the router"),
              );
            }
            return save.call(this, cb, silent);
          });
        });
    };

    // Inject core service
    main.coreService();

    return podkopMap.render();
  },
};

return view.extend(EntryPoint);
