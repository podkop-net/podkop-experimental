"use strict";
"require view";
"require form";
"require view.podkop.main as main";
"require view.podkop.section as section";
"require view.podkop.settings as settings";
"require view.podkop.dashboard as dashboard";
"require view.podkop.diagnostic as diagnostic";
/**
 * Creates a fixed tab backed by a named UCI section.
 *
 * @param {object} map - LuCI form.Map instance
 * @param {string} type - UCI section type and section ID
 * @param {string} title - Tab title
 * @param {Function} configure - Callback to create tab content
 * @returns {object} Created section
 */
function createFixedSection(map, type, title, configure) {
  const section = map.section(
    form.TypedSection,
    type,
    title,
  );

  section.anonymous = true;
  section.addremove = false;
  section.cfgsections = function () {
    return [type];
  };

  configure(section);

  return section;
}

const EntryPoint = {
  async render() {
    main.injectGlobalStyles();

    // Detect features supported by the installed sing-box.
    const singBoxFeatures =
      await main.CustomPodkopMethods.getSingBoxFeatures();

    const podkopMap = new form.Map(
      "podkop",
      _("Podkop Settings"),
      _("Configuration for Podkop service"),
    );

    // Enable tabbed layout.
    podkopMap.tabbed = true;
    
    // Validate proxy links before saving settings.
    const save = podkopMap.save;
    
    podkopMap.save = function (cb, silent) {
      if (silent) {
        return save.call(this, cb, silent);
      }
    
      return main.checkLinksBeforeSave(this).then((problems) => {
        if (problems.length) {
          main.showLinkProblems(problems);
          return Promise.reject(
            new Error("proxy links refused by the router"),
          );
        }
    
        return save.call(this, cb, silent);
      });
    };

    // Sections tab.
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

    section.createSectionContent(
      sectionsSection,
      singBoxFeatures,
    );

    // Keep section options inside the edit modal.
    sectionsSection.children.forEach(function (option) {
      option.modalonly = true;
    });

    // Settings tab.
    createFixedSection(
      podkopMap,
      "settings",
      _("Settings"),
      function (settingsSection) {
        settings.createSettingsContent(
          settingsSection,
          singBoxFeatures,
        );
      },
    );

    // Diagnostics tab.
    createFixedSection(
      podkopMap,
      "diagnostic",
      _("Diagnostics"),
      function (diagnosticSection) {
        diagnostic.createDiagnosticContent(diagnosticSection);
      },
    );

    // Dashboard tab.
    createFixedSection(
      podkopMap,
      "dashboard",
      _("Dashboard"),
      function (dashboardSection) {
        dashboard.createDashboardContent(dashboardSection);
      },
    );

    // Initialize core services.
    main.coreService();

    return podkopMap.render();
  },
};

return view.extend(EntryPoint);
