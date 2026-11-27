"use strict";
"require baseclass";
"require form";
"require ui";
"require uci";
"require fs";
"require network";
"require view.podkop.main as main";
"require view.podkop.devices as devices";

// The provider's DNS servers netifd knows now: those of the interfaces with a default route
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

// The setup wizard hands over the config it made. The sources, the rules with their rows and
// the DNS servers of the file are replaced by those of the wizard, its settings are set, and
// the change is applied: the backend reloads on the change of the file.
function saveWizard(build) {
  const kinds = ["source", "section", "member", "dns_server"];
  return uci.load("podkop").then(() => {
    const taken = [];
    kinds.forEach((kind) => {
      uci.sections("podkop", kind).forEach((old) => {
        taken.push(old[".name"]);
        uci.remove("podkop", old[".name"]);
      });
    });
    const config = build(taken);
    config.sections.forEach((item) => {
      const name = item.name
        ? uci.add("podkop", item.type, item.name)
        : uci.add("podkop", item.type);
      Object.keys(item.options).forEach((key) => {
        uci.set("podkop", name, key, item.options[key]);
      });
    });
    Object.keys(config.settings).forEach((key) => {
      uci.set("podkop", "settings", key, config.settings[key]);
    });
    // Applied without LuCI's rollback: the page is loaded again right after, and a change that
    // waits to be confirmed by the page would be rolled back when the page is gone.
    return uci
      .save()
      .then(() => uci.callApply(10, false))
      .then((code) => (code ? Promise.reject(code) : null));
  });
}

function createDashboardContent(section) {
  // the setup wizard asks the page for the devices an interface source may name
  main.setWizardEnv({
    outDevices: () => devices.listForRole("out"),
    providerDns: providerDNS,
    save: saveWizard,
  });
  const o = section.option(form.DummyValue, "_mount_node");
  o.rawhtml = true;
  o.cfgvalue = () => {
    main.DashboardTab.initController();
    return main.DashboardTab.render();
  };
}

const EntryPoint = {
  createDashboardContent,
};

return baseclass.extend(EntryPoint);
