// Package model holds the settings of the backend as its UCI file of the format 2 states them
// (podkop-exp 0.9; podkop migrate converts the older ones): one "settings" section, the
// sources of servers ("source": a subscription, links, an outbound JSON or a network
// interface), the rules ("section": lists and where their traffic goes) and the rows of the
// rules ("member": a source with a filter of server names, as a server or a fallback). Values
// are kept the way the shell backend read the options it had, defaults included.
package model

import (
	"strings"
	"unicode"

	"github.com/podkop-net/podkop-experimental/src/backend/dataplane"

	"github.com/podkop-net/podkop-experimental/src/backend/migrate"
	"github.com/podkop-net/podkop-experimental/src/backend/uci"
	E "github.com/sagernet/sing/common/exceptions"
)

// Config is the whole file.
type Config struct {
	Settings Settings
	// Sections are the rules in the order of the file: the order decides the order of the
	// route rules, so the first rule a connection matches takes it.
	Sections []Section
	// Sources in the order of the file.
	Sources []Source
}

// Source is a "config source" block: where servers come from.
type Source struct {
	Name string
	// Type is subscription, links, json or interface; "" is a source not filled yet.
	Type string
	// Label is what the page shows; "" lets it name the source itself.
	Label string

	// URL is the address a provider lists its servers at; a secret: the token in it is the
	// account.
	URL string
	// UpdateInterval is how often the list is downloaded again: auto (as the provider
	// says, otherwise a day) or a duration (20m, 1h, …).
	UpdateInterval string

	Links      []string
	UDPOverTCP bool

	OutboundJSON string

	// Interface is the network interface the traffic leaves through; "" is the main route.
	Interface               string
	RoutingMark             string
	DomainResolverEnabled   bool
	DomainResolverDNSType   string
	DomainResolverDNSServer string
}

// Filled tells whether the source names servers: a source the page added and the user has
// not filled yet names none.
// SourceTypes are the types of a source; a source without one is not filled yet.
var SourceTypes = []string{"subscription", "links", "json", "interface"}

func (s *Source) Filled() bool {
	switch s.Type {
	case "subscription":
		return s.URL != ""
	case "links":
		return len(s.Links) > 0
	case "json":
		return strings.TrimSpace(s.OutboundJSON) != ""
	case "interface":
		return true
	}
	return false
}

// The sources a member may name besides the "config source" blocks.
const (
	SourceDirect = "direct"
	SourceBlock  = "block"
)

// Member is a "config member" block: a row of the servers or of the fallbacks of a rule.
type Member struct {
	// Source is the name of a source, SourceDirect or SourceBlock.
	Source string
	// Include are words one of which a name of a server has to start a word of (none: every
	// server), Exclude words none of which it may; letters of any case.
	Include []string
	Exclude []string
	// Via is the source the connections to the servers of the row go through ("": none).
	Via string
}

// Takes tells whether the row takes a server of the name.
func (m *Member) Takes(name string) bool {
	for _, word := range m.Exclude {
		if NameHas(name, word) {
			return false
		}
	}
	if len(m.Include) == 0 {
		return true
	}
	for _, word := range m.Include {
		if NameHas(name, word) {
			return true
		}
	}
	return false
}

// NameHas tells whether a word of the name starts with the word: "AI" finds "USA AI-1" and
// not "Spain". A word with other characters than letters and digits (a flag, a dash, a
// space) is looked for in the name as it is.
func NameHas(name string, word string) bool {
	name, word = strings.ToLower(name), strings.ToLower(strings.TrimSpace(word))
	if word == "" {
		return false
	}
	if strings.IndexFunc(word, notWordRune) >= 0 {
		return strings.Contains(name, word)
	}
	for _, part := range strings.FieldsFunc(name, notWordRune) {
		if strings.HasPrefix(part, word) {
			return true
		}
	}
	return false
}

func notWordRune(r rune) bool {
	return !unicode.IsLetter(r) && !unicode.IsDigit(r)
}

// Check is how the servers are tested: one check for every rule.
type Check struct {
	Interval      string
	Tolerance     string
	TestingURL    string
	DownloadCheck string // default, off, custom
	DownloadURL   string
}

// Settings is the section "settings".
type Settings struct {
	DNSType            string // udp, dot, doh
	DNSServer          string // host[:port][/path]
	BootstrapDNSServer string
	DNSRewriteTTL      string // a number is expected; kept as written

	SourceNetworkInterfaces []string
	OutputNetworkInterface  string
	ExcludeNTP              bool
	RoutingExcludedIPs      []string

	EnableYACD bool
	// YACDInterfaces are the devices YACD is opened from; none: those of
	// SourceNetworkInterfaces
	YACDInterfaces []string
	YACDSecretKey  string
	// UTLSFallback turns the uTLS fingerprint fallback of the engine on
	// (experimental.utls_fallback): on unless the settings turn it off
	// ("utls_fallback" 'disabled'); the page writes nothing for the default
	UTLSFallback bool
	DisableQUIC  bool

	UpdateInterval               string
	DownloadListsViaProxy        bool
	DownloadListsViaProxySection string
	DontTouchDHCP                bool

	CachePath            string
	LogLevel             string
	ServiceListenAddress string

	Check Check
}

// Section is one "config section" block: a rule, which lists name a part of the traffic
// and where that part goes.
type Section struct {
	Name string
	// Label is what the page shows; "" is the name.
	Label   string
	Enabled bool
	// Servers are the rows the servers of the rule come from, Fallbacks the rows used in
	// their order while none of the servers answers.
	Servers   []Member
	Fallbacks []Member

	CommunityLists     []string
	UserDomainListType string // disabled, dynamic, text
	UserDomains        string // the items joined by spaces
	UserDomainsText    string
	UserSubnetListType string
	UserSubnets        string
	UserSubnetsText    string
	LocalDomainLists   []string
	LocalSubnetLists   []string
	RemoteDomainLists  []string
	RemoteSubnetLists  []string

	FullyRoutedIPs          []string
	MixedProxyEnabled       bool
	MixedProxyPort          string
	ResolveRealIPForRouting bool
}

// Load takes the settings out of a parsed file.
func Load(parsed *uci.Package) (*Config, error) {
	// settings of an older format are read as podkop migrate converts them; the file on the
	// disk is converted by the install and by the daemon
	migrate.Convert(parsed)
	settings := parsed.Section("settings")
	if settings == nil || settings.Type != "settings" {
		// the page writes "config settings 'settings'"; a section of another type that
		// takes the name is no settings
		return nil, E.New("the file has no section \"settings\"")
	}
	get := func(section *uci.Section, name string, defaultValue string) string {
		// as the shell's config_get: an option set to nothing takes the default too
		if value := section.Get(name); value != "" {
			return value
		}
		return defaultValue
	}
	config := &Config{Settings: Settings{
		DNSType:                      get(settings, "dns_type", "doh"),
		DNSServer:                    get(settings, "dns_server", "1.1.1.1"),
		BootstrapDNSServer:           get(settings, "bootstrap_dns_server", "77.88.8.8"),
		DNSRewriteTTL:                get(settings, "dns_rewrite_ttl", "60"),
		SourceNetworkInterfaces:      list(settings, "source_network_interfaces"),
		OutputNetworkInterface:       settings.Get("output_network_interface"),
		ExcludeNTP:                   settings.Bool("exclude_ntp", false),
		RoutingExcludedIPs:           list(settings, "routing_excluded_ips"),
		EnableYACD:                   settings.Bool("enable_yacd", false),
		YACDInterfaces:               list(settings, "yacd_interfaces"),
		YACDSecretKey:                settings.Get("yacd_secret_key"),
		UTLSFallback:                 settings.Bool("utls_fallback", true),
		DisableQUIC:                  settings.Bool("disable_quic", false),
		UpdateInterval:               get(settings, "update_interval", "1d"),
		DownloadListsViaProxy:        settings.Bool("download_lists_via_proxy", false),
		DownloadListsViaProxySection: settings.Get("download_lists_via_proxy_section"),
		DontTouchDHCP:                settings.Bool("dont_touch_dhcp", false),
		CachePath:                    CachePath(get(settings, "cache_path", DefaultCachePath)),
		LogLevel:                     get(settings, "log_level", "warn"),
		ServiceListenAddress:         settings.Get("service_listen_address"),
		Check: Check{
			Interval:      get(settings, "urltest_check_interval", "3m"),
			Tolerance:     get(settings, "urltest_tolerance", "50"),
			TestingURL:    get(settings, "urltest_testing_url", "https://www.gstatic.com/generate_204"),
			DownloadCheck: get(settings, "urltest_download_check", "default"),
			DownloadURL:   settings.Get("urltest_download_url"),
		},
	}}

	for _, section := range parsed.SectionsOfType("section") {
		config.Sections = append(config.Sections, Section{
			Name:                    section.Name,
			Label:                   section.Get("label"),
			Enabled:                 section.Bool("enabled", true),
			CommunityLists:          list(section, "community_lists"),
			UserDomainListType:      get(section, "user_domain_list_type", "disabled"),
			UserDomains:             section.Get("user_domains"),
			UserDomainsText:         section.Get("user_domains_text"),
			UserSubnetListType:      get(section, "user_subnet_list_type", "disabled"),
			UserSubnets:             section.Get("user_subnets"),
			UserSubnetsText:         section.Get("user_subnets_text"),
			LocalDomainLists:        list(section, "local_domain_lists"),
			LocalSubnetLists:        list(section, "local_subnet_lists"),
			RemoteDomainLists:       list(section, "remote_domain_lists"),
			RemoteSubnetLists:       list(section, "remote_subnet_lists"),
			FullyRoutedIPs:          list(section, "fully_routed_ips"),
			MixedProxyEnabled:       section.Bool("mixed_proxy_enabled", false),
			MixedProxyPort:          section.Get("mixed_proxy_port"),
			ResolveRealIPForRouting: section.Bool("resolve_real_ip_for_routing", false),
		})
	}
	for _, section := range parsed.SectionsOfType("source") {
		if section.Name == SourceDirect || section.Name == SourceBlock {
			return nil, E.New("a source cannot be named ", section.Name, ": the word names where a row goes without a server")
		}
		config.Sources = append(config.Sources, Source{
			Name:                    section.Name,
			Type:                    section.Get("type"),
			Label:                   section.Get("label"),
			URL:                     strings.TrimSpace(section.Get("url")),
			UpdateInterval:          get(section, "update_interval", "auto"),
			Links:                   nonEmpty(links(section, "link")),
			UDPOverTCP:              section.Get("udp_over_tcp") == "1",
			OutboundJSON:            section.Get("outbound_json"),
			Interface:               section.Get("interface"),
			RoutingMark:             section.Get("routing_mark"),
			DomainResolverEnabled:   isOne(section.Get("domain_resolver_enabled")),
			DomainResolverDNSType:   get(section, "domain_resolver_dns_type", "udp"),
			DomainResolverDNSServer: section.Get("domain_resolver_dns_server"),
		})
	}
	for _, member := range parsed.SectionsOfType("member") {
		rule := config.Section(member.Get("section"))
		if rule == nil {
			// a row of a rule deleted on the page: nothing to go to
			continue
		}
		row := Member{Source: member.Get("source"), Include: words(member, "include"), Exclude: words(member, "exclude"), Via: member.Get("via")}
		if member.Get("role") == "fallback" {
			rule.Fallbacks = append(rule.Fallbacks, row)
		} else {
			rule.Servers = append(rule.Servers, row)
		}
	}
	return config, nil
}

// words returns the items of a list option without the empty ones and the spaces around
// them; an item may have spaces inside.
func words(section *uci.Section, name string) []string {
	var result []string
	for _, item := range section.List(name) {
		if item = strings.TrimSpace(item); item != "" {
			result = append(result, item)
		}
	}
	return result
}

// Source returns the source of the name, or nil.
func (c *Config) Source(name string) *Source {
	for index := range c.Sources {
		if c.Sources[index].Name == name {
			return &c.Sources[index]
		}
	}
	return nil
}

// Section returns the section of the name, or nil.
func (c *Config) Section(name string) *Section {
	for index := range c.Sections {
		if c.Sections[index].Name == name {
			return &c.Sections[index]
		}
	}
	return nil
}

// list returns the items of a list option; none when all there is to it is empty items,
// which the shell backend takes for an option that is not set.
func list(section *uci.Section, name string) []string {
	if section.Get(name) == "" {
		return nil
	}
	return section.List(name)
}

// isOne tells whether the text is the number one for the shell's "-eq": spaces around it
// and zeros before it allowed. The shell backend reads one switch this way.
func isOne(text string) bool {
	text = strings.TrimPrefix(strings.Trim(text, " \t\n"), "+")
	if text == "" {
		return false
	}
	for index := 0; index < len(text)-1; index++ {
		if text[index] != '0' {
			return false
		}
	}
	return text[len(text)-1] == '1'
}

// links splits a list of proxy links the way the shell backend walks it: by white space,
// so a link written with a space in it is two words there as well.
func links(section *uci.Section, name string) []string {
	return strings.Fields(section.Get(name))
}

// nonEmpty is nil for no items, as a list that is not set reads.
func nonEmpty(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	return items
}

// HasEnabledLists tells whether the section names any traffic: without a list it has no
// route rule of its own.
func (s *Section) HasEnabledLists() bool {
	return len(s.CommunityLists) > 0 ||
		s.UserDomainListType != "disabled" ||
		s.UserSubnetListType != "disabled" ||
		len(s.LocalDomainLists) > 0 ||
		len(s.LocalSubnetLists) > 0 ||
		len(s.RemoteDomainLists) > 0 ||
		len(s.RemoteSubnetLists) > 0
}

// Where the traffic of a rule goes (Config.Exit).
const (
	// ExitNone: no row names a filled source; the rule does nothing yet
	ExitNone = ""
	// ExitDirect and ExitBlock: the one row of the servers is direct or block, a route
	// rule as a section of the type exclusion or block was
	ExitDirect = "direct"
	ExitBlock  = "block"
	// ExitServers: through the outbound of the rule, a selector over its servers
	ExitServers = "servers"
)

// Exit tells where the traffic of the rule goes.
func (c *Config) Exit(s *Section) string {
	// rows of the servers that are all direct, or all block, are one row of it
	if len(s.Servers) > 0 && len(s.Fallbacks) == 0 {
		first := s.Servers[0].Source
		same := first == SourceDirect || first == SourceBlock
		for _, row := range s.Servers[1:] {
			same = same && row.Source == first
		}
		switch {
		case same && first == SourceDirect:
			return ExitDirect
		case same && first == SourceBlock:
			return ExitBlock
		}
	}
	for _, row := range append(append([]Member{}, s.Servers...), s.Fallbacks...) {
		if row.Source == SourceDirect || row.Source == SourceBlock {
			return ExitServers
		}
		if source := c.Source(row.Source); source != nil && source.Filled() {
			return ExitServers
		}
	}
	return ExitNone
}

// Routes tells whether a rule that is on goes somewhere. Without one sing-box has nothing to
// do (a fresh install, every source emptied) and the router is left alone.
func (c *Config) Routes() bool {
	for index := range c.Sections {
		if c.Sections[index].Enabled && c.Exit(&c.Sections[index]) != ExitNone {
			return true
		}
	}
	return false
}

// HasOutbound tells whether traffic of the rule leaves through an outbound of its own.
func (c *Config) HasOutbound(s *Section) bool {
	return s.Enabled && c.Exit(s) == ExitServers
}

// FormatVersion is the format of the settings this backend reads (settings.config_version).
const FormatVersion = migrate.Version

// DefaultCachePath is the cache file of sing-box (FakeIP, rule sets) when the settings name
// none: in RAM, as the shell backend had it.
const DefaultCachePath = dataplane.RunDir + "/cache.db"

// movedDirs are the directories of the sing-box package that podkop 0.7 offered for the
// cache file, and where the backend has it instead.
var movedDirs = [][2]string{
	{"/tmp/sing-box/", dataplane.RunDir + "/"},
	{"/usr/share/sing-box/", dataplane.DataDir + "/"},
}

// CachePath is the cache file the settings name, a path in a directory of the sing-box
// package taken to the same name in the backend's own: settings kept from podkop 0.7 name
// those. The package moves the file there once (uci-defaults), so the FakeIP addresses
// handed out before stay.
func CachePath(path string) string {
	for _, moved := range movedDirs {
		if rest, found := strings.CutPrefix(path, moved[0]); found {
			return moved[1] + rest
		}
	}
	return path
}
