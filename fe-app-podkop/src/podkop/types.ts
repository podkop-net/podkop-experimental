// eslint-disable-next-line @typescript-eslint/no-namespace
export namespace ClashAPI {
  export interface ProxyHistoryEntry {
    time: string;
    delay: number;
  }

  export interface ProxyBase {
    type: string;
    name: string;
    udp: boolean;
    history: ProxyHistoryEntry[];
    now?: string;
    all?: string[];
    // the end of all that a delay test of a URL test leaves out
    fallbacks?: string[];
    // what the loss probes of a server counted (podkop-engine urltest modes)
    loss?: ProxyLoss;
    // the mode of a URL test other than fastest: loss or balance
    mode?: string;
    // the servers of a balance and the devices each carries
    balance?: { name: string; devices: number }[];
  }

  export interface ProxyLoss {
    windows?: {
      hours: number;
      probes: number;
      segments: number;
      lost: number;
    }[];
    rtt?: number;
    not_counted?: string;
  }

  export interface Proxies {
    proxies: Record<string, ProxyBase>;
    // what the outbounds are (the backend's plan.Tags), added by podkop: the tags are made of
    // the names of the rules and the sources and are not taken apart
    podkop_tags?: Podkop.Tags;
  }
}

// eslint-disable-next-line @typescript-eslint/no-namespace
export namespace Podkop {
  // Available commands:
  // start                   Start podkop service
  // stop                    Stop podkop service
  // reload                  Reload podkop configuration
  // restart                 Restart podkop service
  // enable                  Enable podkop autostart
  // disable                 Disable podkop autostart
  // main                    Run main podkop process
  // list_update             Update domain lists
  // check_proxy             Check proxy connectivity
  // check_nft               Check NFT rules
  // check_nft_rules         Check NFT rules status
  // check_sing_box          Check sing-box installation and status
  // check_logs              Show podkop logs from system journal
  // check_sing_box_logs     Show sing-box logs
  // check_fakeip            Test FakeIP on router
  // clash_api               Clash API interface for managing proxies and groups
  // show_config             Display current podkop configuration
  // show_version            Show podkop version
  // show_sing_box_config    Show sing-box configuration
  // show_sing_box_version   Show sing-box version
  // show_system_info        Show system information
  // get_status              Get podkop service status
  // get_sing_box_status     Get sing-box service status
  // check_dns_available     Check DNS server availability
  // global_check            Run global system check

  export enum AvailableMethods {
    CHECK_DNS_AVAILABLE = 'check_dns_available',
    CHECK_FAKEIP = 'check_fakeip',
    CHECK_FAKEIP_CLIENT = 'check_fakeip_client',
    CHECK_NFT_RULES = 'check_nft_rules',
    GET_STATUS = 'get_status',
    CHECK_SING_BOX = 'check_sing_box',
    GET_SING_BOX_STATUS = 'get_sing_box_status',
    CLASH_API = 'clash_api',
    RESTART = 'restart',
    START = 'start',
    STOP = 'stop',
    ENABLE = 'enable',
    DISABLE = 'disable',
    GLOBAL_CHECK = 'global_check',
    SHOW_SING_BOX_CONFIG = 'show_sing_box_config',
    CHECK_LINKS = 'check_links',
    CHECK_LOGS = 'check_logs',
    GET_SYSTEM_INFO = 'get_system_info',
    GET_SING_BOX_FEATURES = 'get_sing_box_features',
    SUBSCRIPTION_LOAD = 'subscription_load',
    SUBSCRIPTION_LOAD_START = 'subscription_load_start',
    SUBSCRIPTION_LOAD_STATE = 'subscription_load_state',
    SUBSCRIPTION_LOAD_CANCEL = 'subscription_load_cancel',
    SUBSCRIPTION_STATUS = 'subscription_status',
    SUBSCRIPTION_UPDATE_START = 'subscription_update_start',
    GROUP_CHECK = 'group_check',
  }

  export enum AvailableClashAPIMethods {
    GET_PROXIES = 'get_proxies',
    GET_PROXY_LATENCY = 'get_proxy_latency',
    GET_GROUP_LATENCY = 'get_group_latency',
    SET_GROUP_PROXY = 'set_group_proxy',
  }

  // the block a server is under, from the backend's detector (detect.Verdict)
  export type Block =
    | 'none'
    | 'limit'
    | 'freeze'
    | 'wrongparams'
    | 'rejected'
    | 'hellodrop'
    | 'pathblock'
    | 'dead'
    | 'unreachable'
    | 'unknown';

  export type VerdictNote =
    | 'needs_mlkem'
    | 'fp_switched'
    | 'handshake_failed'
    | 'cured'
    | 'fallback_off'
    | 'clock_suspect'
    | 'burst_any_fp'
    | 'uplink_down'
    | 'dns_failed'
    | 'target_failed'
    | 'download_test'
    | 'inconclusive'
    | 'some_lost'
    | 'through_detour'
    | 'not_applicable'
    | 'probe_hello_refused'
    | 'relay_silent'
    | 'tls_cert'
    | 'stand_in'
    | 'upgrade_in_dial'
    | 'server_silent';

  // what the page shows of a verdict; the English why of the backend is for logs and the CLI
  export interface Verdict {
    block: Block;
    source: 'passive' | 'active';
    notes?: VerdictNote[];
    fp?: string;
    kb?: number;
    n?: number;
  }

  // a verdict as the method detect answers it
  export interface VerdictReply extends Verdict {
    // seconds since the probe, of a verdict of a probe; absent when 0
    age?: number;
    why?: string;
  }

  // the treatment set on a server (detect.Cure / model.Cure). spoof = tls.spoof for the limit;
  // record_fragment is the freeze cure that keeps the fingerprint. spoof needs the server's own
  // socket, so the backend refuses it through a proxy (an interface gives one).
  export type CureKind = 'spoof' | 'record_fragment';

  export interface Cure {
    kind: CureKind;
    // only for spoof: the whitelisted name put on the wire
    sni?: string;
  }

  // a server's stable identity, the path it is reached through, and its stored cure, as the detect
  // report carries them beside the verdicts (keyed by the same tag the page uses as outbound.code)
  export interface ServerCure {
    // the tag-stripped stable identity (detect.Server.Hash); the cure key and a render-time guard
    hash: string;
    // the through-source name; '' means the server is reached directly, matches plan TagOf.Via
    via: string;
    // the source of via is an interface: the server has its own socket, a mask works
    via_interface?: boolean;
    cure?: Cure;
  }

  // the answer of the method detect of the object podkop on ubus
  export interface DetectReport {
    verdicts: Record<string, VerdictReply>;
    probing: string;
    queued: string[];
    noprobe: string[];
    fallback: boolean;
    // every probe-eligible server, and any server that merely has a cure stored (so the badge
    // renders without a verdict); parallel to verdicts, keyed by tag
    servers?: Record<string, ServerCure>;
    // the stored treatments of no server in use, and rows this build cannot read
    stale_cures?: number;
  }

  // the answer of set_cure / clear_cure; denied is not of the backend: rpc.js refused the call
  // (the ACL of the session), as with ForceDetectReply
  export interface CureReply {
    state:
      | 'ok'
      | 'via_detour'
      | 'unknown'
      | 'invalid'
      | 'not_running'
      | 'denied';
  }

  // the answer of suggest_mask: the in-engine white-SNI probe, found with the name it found
  export interface SuggestMaskReply {
    state:
      | 'found'
      | 'none'
      | 'not_running'
      | 'canceled'
      | 'throttled'
      | 'running'
      | 'busy'
      | 'denied';
    sni?: string;
    tried?: number;
    retry_after?: number;
  }

  // the new write methods of the object podkop on ubus (write.ubus.podkop)
  export enum CureMethods {
    SET_CURE = 'set_cure',
    CLEAR_CURE = 'clear_cure',
    DROP_STALE_CURES = 'drop_stale_cures',
    SUGGEST_MASK = 'suggest_mask',
  }

  // the answer of the method force_detect; the verdict comes in a later detect
  export interface ForceDetectReply {
    state:
      | 'started'
      | 'queued'
      | 'running'
      | 'throttled'
      | 'unknown'
      | 'not_running'
      | 'canceled'
      // not of the backend: rpc.js was refused the call (getVerdicts.ts forceDetect)
      | 'denied';
    retry_after?: number;
  }

  export interface Outbound {
    code: string;
    displayName: string;
    latency: number;
    type: string;
    selected: boolean;
    // the connections of some rule go through it: selected, or the choice of the selected URL test
    inUse: boolean;
    // the connections of this rule go through it: the end of the choices of its selector
    active?: boolean;
    // the choice of the URL test of a fallback of several servers whose turn has not come
    pick?: boolean;
    // the place of its tier in the order the rule takes them: 0 its servers, n its fallback n
    tier?: number;
    // false for what the selector does not offer (direct or block as a fallback): no click pins it
    selectable?: boolean;
    // the loss its probes counted, as shown ("0.4%"), and the windows, for the title
    loss?: string;
    lossTitle?: string;
    lossPreliminary?: boolean;
    lossTone?: 'ok' | 'warn' | 'error';
    // a server of the balance of the rule, and the devices it carries
    balanced?: boolean;
    devices?: number;
    // merged from the detect report at render; the authoritative source is the report, not the tile
    hash?: string;
    via?: string;
    via_interface?: boolean;
    cure?: Cure;
  }

  // Where the connections of a rule go now. auto: by its URL test, from its servers (tier 0) or
  // from its fallback tier; manual: a server pinned on the dashboard; single: the one server of
  // a rule that has nothing to choose from.
  export interface OutboundRoute {
    mode: 'auto' | 'manual' | 'single';
    tier: number;
    code: string;
    displayName: string;
    latency: number;
    // how the URL test of the rule chooses, when not by the delay alone
    choice?: 'loss' | 'balance';
    // the servers of the balance, by name
    balance?: string[];
  }

  // what an outbound is, by the sections of the settings: a group of a rule (of its fallback row
  // from 1), a server of a source (its name there; none for a source of one server, through a
  // source), the URL test of the servers of a source rows go through
  export interface TagOf {
    rule?: string;
    fallback?: number;
    source?: string;
    server?: string;
    via?: string;
  }

  // the outbounds of a rule: its selector and the URL test of its servers
  export interface RuleTags {
    name: string;
    selector: string;
    test?: string;
  }

  export interface Tags {
    rules?: Record<string, RuleTags>;
    outbounds?: Record<string, TagOf>;
  }

  export interface OutboundGroup {
    withTagSelect: boolean;
    // the section of the rule
    rule?: string;
    code: string;
    displayName: string;
    outbounds: Outbound[];
    // the names of the tiers, in the order the rule takes them; none without fallbacks
    tiers?: string[];
    // the URL test of the rule, which the selector takes unless a server is pinned
    auto?: string;
    route?: OutboundRoute;
  }

  // a "config section" block of format 2: a rule (tab Rules)
  export interface ConfigRule {
    '.name': string;
    '.type'?: 'section';
    label?: string;
    enabled?: string;
    community_lists?: string[];
    user_domain_list_type?: string;
    user_domains?: string[];
    user_domains_text?: string;
    user_subnet_list_type?: string;
    user_subnets?: string[];
    user_subnets_text?: string;
    local_domain_lists?: string[];
    remote_domain_lists?: string[];
    local_subnet_lists?: string[];
    remote_subnet_lists?: string[];
    fully_routed_ips?: string[];
    mixed_proxy_enabled?: string;
    mixed_proxy_port?: string;
    resolve_real_ip_for_routing?: string;
  }

  // a "config source" block: where servers come from (tab Servers)
  export interface ConfigSource {
    '.name': string;
    '.type'?: 'source';
    type?: string;
    label?: string;
    url?: string;
    update_interval?: string;
    link?: string | string[];
    udp_over_tcp?: string;
    outbound_json?: string;
    interface?: string;
    routing_mark?: string;
    domain_resolver_enabled?: string;
    domain_resolver_dns_type?: string;
    domain_resolver_dns_server?: string;
  }

  // a "config member" block: a row of the servers or of the fallbacks of a rule, in the
  // order of the file
  export interface ConfigMember {
    '.name': string;
    '.type'?: 'member';
    section?: string;
    role?: string;
    source?: string;
    include?: string | string[];
    exclude?: string | string[];
    via?: string;
  }

  // the rules, sources and rows of the settings
  export interface ConfigModel {
    rules: ConfigRule[];
    sources: ConfigSource[];
    members: ConfigMember[];
  }

  // a block of the file other than a source or a row: the settings or a rule
  export type ConfigSection = {
    '.name': string;
    '.type': 'settings' | 'section';
    yacd_secret_key?: string;
    label?: string;
    enabled?: string;
  };

  export interface MethodSuccessResponse<T> {
    success: true;
    data: T;
  }

  export interface MethodFailureResponse {
    success: false;
    error: string;
  }

  export type MethodResponse<T> =
    | MethodSuccessResponse<T>
    | MethodFailureResponse;

  // a DNS server of the list; providers are the provider's servers of its row
  export interface DnsCheckServer {
    type: 'udp' | 'doh' | 'dot' | 'provider';
    server: string;
    providers?: string[];
    status: 0 | 1;
    // the rcode of a server that replied without an answer (REFUSED, SERVFAIL), status 0
    refusal?: string;
  }

  export interface DnsCheckResult {
    // the first server of the list, and whether any server of it answers
    dns_type: 'udp' | 'doh' | 'dot' | 'provider';
    dns_server: string;
    dns_status: 0 | 1;
    dns_mode?: string;
    dns_servers?: DnsCheckServer[];
    dns_on_router: 0 | 1;
    bootstrap_dns_server: string;
    bootstrap_dns_status: 0 | 1;
    dhcp_config_status: 0 | 1;
  }

  export interface NftRulesCheckResult {
    table_exist: 0 | 1;
    rules_mangle_exist: 0 | 1;
    rules_mangle_counters: 0 | 1;
    rules_mangle_output_exist: 0 | 1;
    rules_mangle_output_counters: 0 | 1;
    rules_proxy_exist: 0 | 1;
    rules_proxy_counters: 0 | 1;
    rules_other_mark_exist: 0 | 1;
  }

  export interface SingBoxCheckResult {
    sing_box_installed: 0 | 1;
    sing_box_version_ok: 0 | 1;
    sing_box_service_exist: 0 | 1;
    sing_box_autostart_disabled: 0 | 1;
    sing_box_process_running: 0 | 1;
    sing_box_ports_listening: 0 | 1;
  }

  export interface FakeIPCheckResult {
    fakeip: boolean;
    IP: string;
  }

  // the lines of the log a reader has not seen, and the cursor to ask with next
  // what check_links tells of a link: whether the engine of the router takes it, and why not
  export interface LinkCheck {
    ok: boolean;
    error?: string;
  }

  // a list of a subscription downloaded to be shown (subscription_load)
  export interface PreviewServer {
    name: string;
    scheme: string;
    address?: string;
    link: string;
    reason?: string;
    notes?: string[];
  }

  // a try of a download by one way: how far it came, how long, how much, and why it failed
  export interface Attempt {
    route: string;
    phase: 'connect' | 'tls' | 'wait' | 'body' | 'done' | 'failed' | 'canceled';
    ms: number;
    first_byte_ms?: number;
    bytes?: number;
    error?: string;
    code?: string;
    args?: string[];
  }

  // what a provider tells of a subscription with its list (the headers of the list)
  export interface ProviderInfo {
    title?: string;
    upload?: number;
    download?: number;
    total?: number;
    traffic?: boolean;
    expire?: string;
    refill?: string;
    update_hours?: number;
    support_url?: string;
    web_page_url?: string;
    announce?: string;
  }

  export interface SubscriptionPreview {
    route?: string;
    error?: string;
    error_code?: string;
    error_args?: string[];
    took_ms?: number;
    attempts?: Attempt[];
    provider?: ProviderInfo;
    servers: PreviewServer[];
  }

  // a download of a list for the page, under way or done (subscription_load_start, _state)
  export interface LoadJob {
    id: string;
    state: 'running' | 'done' | 'failed' | 'canceled';
    elapsed_ms: number;
    attempts: Attempt[];
    preview?: SubscriptionPreview;
  }

  // which servers a row of a rule would take from a subscription (group_check)
  export interface GroupCheck {
    subscriptions: string[];
    include: string[];
    exclude: string[];
    // the addresses by the name of the source: one not saved yet has its address there only
    addresses?: Record<string, string>;
  }

  export interface GroupPreview {
    chosen: string[];
    total: number;
    missing?: string[];
  }

  // what the backend knows of a subscription (subscription_status)
  export interface SubscriptionState {
    name: string;
    servers: number;
    usable: number;
    changed?: string;
    checked?: string;
    route?: string;
    error?: string;
    error_code?: string;
    error_args?: string[];
    attempted?: string;
    took_ms?: number;
    attempts?: Attempt[];
    next?: string;
    busy?: boolean;
    provider?: ProviderInfo;
    now?: string;
  }

  export interface FakeIPClientCheckResult {
    dns: boolean;
    connection: boolean;
    client?: string;
    address?: string;
  }

  export interface GetStatus {
    enabled: number;
    status: string;
  }

  export interface GetSingBoxStatus {
    running: number;
    enabled: number;
    status: string;
  }

  // the answer of the method stats of the backend's object on ubus
  export interface Stats {
    running: boolean;
    // milliseconds of a clock of the backend
    at: number;
    up: number;
    down: number;
    connections: number;
    memory: number;
  }

  export interface GetSystemInfo {
    podkop_version: string;
    podkop_latest_version: string;
    luci_app_version: string;
    sing_box_version: string;
    // what the sing-box inside is: "sing-box 1.14.3, podkop-engine r15, slim (1d47804dc783)"
    engine?: string;
    openwrt_version: string;
    device_model: string;
  }

  export interface GetClashApiProxyLatency {
    delay: number;
    message?: string;
  }

  export type GetClashApiGroupLatency = Record<string, number>;
}
