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

// Sections content
"require view.podkop.section as section";

// Groups and subscriptions content
"require view.podkop.group as group";
"require view.podkop.subscription as subscription";

// Dashboard content
"require view.podkop.dashboard as dashboard";

// Diagnostic content
"require view.podkop.diagnostic as diagnostic";

// Sections, groups and subscriptions are sections of one file, and its names are one
// namespace: a group named as a section would merge into it. A name taken is refused.
function uniqueNames(typedSection) {
  const add = typedSection.handleAdd;
  typedSection.handleAdd = function (ev, name) {
    if (name && uci.get("podkop", name)) {
      ui.addNotification(
        null,
        E("p", {}, [
          _(
            "The name %s is taken: sections, groups and subscriptions need names of their own",
          ).format(name),
        ]),
        "error",
      );
      return Promise.resolve();
    }
    return add.apply(this, arguments);
  };
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

    // A save by the user first asks the router about the proxy links of every section: one
    // its engine refuses keeps the settings from being saved, with its field and the reason.
    // The silent saves of LuCI (a section added or removed) are left alone.
    const save = podkopMap.save;
    podkopMap.save = function (cb, silent) {
      if (silent) {
        return save.call(this, cb, silent);
      }
      return main.checkLinksBeforeSave(this).then((problems) => {
        if (problems.length) {
          main.showLinkProblems(problems);
          return Promise.reject(new Error("proxy links refused by the router"));
        }
        return save.call(this, cb, silent);
      });
    };

    // The tabs in the order the traffic is set up: where the servers come from, the groups
    // of them, the sections that send traffic to a group
    // Subscriptions tab: the addresses providers list their servers at
    const subscriptionsSection = podkopMap.section(
      form.TypedSection,
      "subscription",
      _("Subscriptions"),
    );
    subscriptionsSection.anonymous = false;
    subscriptionsSection.addremove = true;
    subscription.createSubscriptionContent(subscriptionsSection);
    uniqueNames(subscriptionsSection);

    // Groups tab: servers of subscriptions chosen by their names
    const groupsSection = podkopMap.section(
      form.GridSection,
      "group",
      _("Groups"),
    );
    groupsSection.anonymous = false;
    groupsSection.addremove = true;
    groupsSection.sortable = true;
    groupsSection.modalpopup = true;

    groupsSection.modaltitle = function (sectionId) {
      return _("Group") + ": " + sectionId;
    };

    group.createGroupContent(groupsSection);
    uniqueNames(groupsSection);

    // Keep group options inside the edit modal.
    groupsSection.children.forEach(function (option) {
      option.modalonly = true;
    });

    // Sections tab
    const sectionsSection = podkopMap.section(
      form.GridSection,
      "section",
      _("Sections"),
    );
    sectionsSection.anonymous = false;
    sectionsSection.addremove = true;
    sectionsSection.sortable = true;
    sectionsSection.modalpopup = true;

    sectionsSection.modaltitle = function (sectionId) {
      return _("Section") + ": " + sectionId;
    };

    // Render section content
    section.createSectionContent(sectionsSection, singBoxFeatures);
    uniqueNames(sectionsSection);

    // Keep section options inside the edit modal.
    sectionsSection.children.forEach(function (option) {
      option.modalonly = true;
    });

    // Settings tab
    const settingsSection = podkopMap.section(
      form.TypedSection,
      "settings",
      _("Settings"),
    );
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
    dashboardSection.anonymous = true;
    dashboardSection.addremove = false;
    dashboardSection.cfgsections = function () {
      return ["dashboard"];
    };

    // Render dashboard content
    dashboard.createDashboardContent(dashboardSection);

    // Inject core service
    main.coreService();

    return podkopMap.render();
  },
};

return view.extend(EntryPoint);
