import { callBaseMethod } from './callBaseMethod';
import { ClashAPI, Podkop } from '../../types';

export const PodkopShellMethods = {
  checkDNSAvailable: async () =>
    callBaseMethod<Podkop.DnsCheckResult>(
      Podkop.AvailableMethods.CHECK_DNS_AVAILABLE,
    ),
  checkFakeIP: async () =>
    callBaseMethod<Podkop.FakeIPCheckResult>(
      Podkop.AvailableMethods.CHECK_FAKEIP,
    ),
  checkFakeIPClient: async (label: string) =>
    callBaseMethod<Podkop.FakeIPClientCheckResult>(
      Podkop.AvailableMethods.CHECK_FAKEIP_CLIENT,
      [label],
    ),
  checkNftRules: async (label: string) =>
    callBaseMethod<Podkop.NftRulesCheckResult>(
      Podkop.AvailableMethods.CHECK_NFT_RULES,
      [label],
    ),
  getStatus: async () =>
    callBaseMethod<Podkop.GetStatus>(Podkop.AvailableMethods.GET_STATUS),
  checkSingBox: async () =>
    callBaseMethod<Podkop.SingBoxCheckResult>(
      Podkop.AvailableMethods.CHECK_SING_BOX,
    ),
  getSingBoxStatus: async () =>
    callBaseMethod<Podkop.GetSingBoxStatus>(
      Podkop.AvailableMethods.GET_SING_BOX_STATUS,
    ),
  getClashApiProxies: async () =>
    callBaseMethod<ClashAPI.Proxies>(Podkop.AvailableMethods.CLASH_API, [
      Podkop.AvailableClashAPIMethods.GET_PROXIES,
    ]),
  getClashApiProxyLatency: async (tag: string) =>
    callBaseMethod<Podkop.GetClashApiProxyLatency>(
      Podkop.AvailableMethods.CLASH_API,
      [Podkop.AvailableClashAPIMethods.GET_PROXY_LATENCY, tag, '5000'],
    ),
  getClashApiGroupLatency: async (tag: string) =>
    callBaseMethod<Podkop.GetClashApiGroupLatency>(
      Podkop.AvailableMethods.CLASH_API,
      [Podkop.AvailableClashAPIMethods.GET_GROUP_LATENCY, tag, '10000'],
    ),
  setClashApiGroupProxy: async (group: string, proxy: string) =>
    callBaseMethod<unknown>(Podkop.AvailableMethods.CLASH_API, [
      Podkop.AvailableClashAPIMethods.SET_GROUP_PROXY,
      group,
      proxy,
    ]),
  restart: async () =>
    callBaseMethod<unknown>(
      Podkop.AvailableMethods.RESTART,
      [],
      '/etc/init.d/podkop',
    ),
  start: async () =>
    callBaseMethod<unknown>(
      Podkop.AvailableMethods.START,
      [],
      '/etc/init.d/podkop',
    ),
  stop: async () =>
    callBaseMethod<unknown>(
      Podkop.AvailableMethods.STOP,
      [],
      '/etc/init.d/podkop',
    ),
  enable: async () =>
    callBaseMethod<unknown>(
      Podkop.AvailableMethods.ENABLE,
      [],
      '/etc/init.d/podkop',
    ),
  disable: async () =>
    callBaseMethod<unknown>(
      Podkop.AvailableMethods.DISABLE,
      [],
      '/etc/init.d/podkop',
    ),
  // with the label and the port of a check name this browser opens connections to while
  // the report is made, the report tells what became of them (it waits up to 5 s for one)
  globalCheck: async (label?: string, port?: number) =>
    callBaseMethod<unknown>(
      Podkop.AvailableMethods.GLOBAL_CHECK,
      label && port ? [label, String(port)] : [],
      '/usr/bin/podkop',
      // LuCI aborts a call after 20 s whatever is asked here
      19000,
    ),
  showSingBoxConfig: async () =>
    callBaseMethod<unknown>(Podkop.AvailableMethods.SHOW_SING_BOX_CONFIG),
  checkLinks: async (links: string[]) =>
    callBaseMethod<Podkop.LinkCheck[]>(
      Podkop.AvailableMethods.CHECK_LINKS,
      links,
    ),
  checkLogs: async () =>
    callBaseMethod<unknown>(Podkop.AvailableMethods.CHECK_LOGS),
  getSystemInfo: async () =>
    callBaseMethod<Podkop.GetSystemInfo>(
      Podkop.AvailableMethods.GET_SYSTEM_INFO,
    ),
  getSingBoxFeatures: async () =>
    callBaseMethod<string[]>(Podkop.AvailableMethods.GET_SING_BOX_FEATURES),
  // the router downloads the list of an address of the form: directly, or through its
  // servers when the provider is blocked; LuCI aborts a call after 20 s
  subscriptionLoad: async (address: string) =>
    callBaseMethod<Podkop.SubscriptionPreview>(
      Podkop.AvailableMethods.SUBSCRIPTION_LOAD,
      [address],
      '/usr/bin/podkop',
      19000,
    ),
  // the same as a job of the router the page asks about: a download is not bound by the 20 s
  // of a call (start, state, cancel; each answers at once)
  subscriptionLoadStart: async (address: string) =>
    callBaseMethod<Podkop.LoadJob>(
      Podkop.AvailableMethods.SUBSCRIPTION_LOAD_START,
      [address],
      '/usr/bin/podkop',
      5000,
    ),
  subscriptionLoadState: async (id: string) =>
    callBaseMethod<Podkop.LoadJob>(
      Podkop.AvailableMethods.SUBSCRIPTION_LOAD_STATE,
      [id],
      '/usr/bin/podkop',
      5000,
    ),
  subscriptionLoadCancel: async (id: string) =>
    callBaseMethod<Podkop.LoadJob>(
      Podkop.AvailableMethods.SUBSCRIPTION_LOAD_CANCEL,
      [id],
      '/usr/bin/podkop',
      5000,
    ),
  subscriptionStatus: async () =>
    callBaseMethod<Podkop.SubscriptionState[]>(
      Podkop.AvailableMethods.SUBSCRIPTION_STATUS,
    ),
  groupCheck: async (check: Podkop.GroupCheck) =>
    callBaseMethod<Podkop.GroupPreview>(
      Podkop.AvailableMethods.GROUP_CHECK,
      [JSON.stringify(check)],
      '/usr/bin/podkop',
      19000,
    ),
};
