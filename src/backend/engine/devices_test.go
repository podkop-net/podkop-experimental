package engine

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/podkop-net/podkop-experimental/src/backend/model"
	"github.com/podkop-net/podkop-experimental/src/backend/plan"
	"github.com/podkop-net/podkop-experimental/src/backend/uci"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"github.com/stretchr/testify/require"
)

// ruleSetRouter is the router the route rules ask for their rule sets by their tags.
type ruleSetRouter struct {
	adapter.Router
	sets map[string]adapter.RuleSet
}

func (r *ruleSetRouter) RuleSet(tag string) (adapter.RuleSet, bool) {
	set, found := r.sets[tag]
	return set, found
}

// routeRules are the route rules of a configuration that end a connection's way (route, reject),
// built by this engine with the rule sets the configuration names, the local files read.
func routeRules(t *testing.T, configuration []byte) []adapter.Rule {
	t.Helper()
	ctx := boxContext(context.Background(), Services{})
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, configuration)
	require.NoError(t, err)
	logger := log.NewNOPFactory().NewLogger("")
	sets := make(map[string]adapter.RuleSet)
	for _, ruleSet := range options.Route.RuleSet {
		for _, tag := range ruleSet.Tag {
			set, err := rule.NewRuleSet(ctx, logger, tag, ruleSet)
			require.NoError(t, err, tag)
			t.Cleanup(func() { set.Close() })
			sets[tag] = set
		}
	}
	ctx = service.ContextWith[adapter.Router](ctx, &ruleSetRouter{sets: sets})
	var rules []adapter.Rule
	for _, entry := range options.Route.Rules {
		if entry.Type != "" && entry.Type != C.RuleTypeDefault {
			continue
		}
		if action := entry.DefaultOptions.Action; action != C.RuleActionTypeRoute && action != C.RuleActionTypeReject {
			continue
		}
		built, err := rule.NewRule(ctx, logger, entry, false)
		require.NoError(t, err)
		require.NoError(t, built.Start())
		t.Cleanup(func() { built.Close() })
		rules = append(rules, built)
	}
	return rules
}

// routeOf is where the first rule that matches sends a connection, as the router matches them:
// the outbound, "reject", or "final" when none matches.
func routeOf(rules []adapter.Rule, inbound string, source string, destination string) string {
	metadata := adapter.InboundContext{Inbound: inbound, Network: N.NetworkTCP, Source: M.SocksaddrFrom(netip.MustParseAddr(source), 40000)}
	if address, err := netip.ParseAddr(destination); err == nil {
		metadata.Destination = M.SocksaddrFrom(address, 443)
	} else {
		// a FakeIP address mapped back to its name, the name sniffed
		metadata.Destination = M.Socksaddr{Fqdn: destination, Port: 443}
		metadata.Domain = destination
	}
	for _, entry := range rules {
		metadata.ResetRuleCache()
		if !entry.Match(&metadata) {
			continue
		}
		switch action := entry.Action().(type) {
		case *rule.RuleActionRoute:
			return action.Outbound
		case *rule.RuleActionReject:
			return "reject"
		}
		return entry.Action().Type()
	}
	return "final"
}

func devicesSettings(t *testing.T, settings string) *model.Config {
	t.Helper()
	parsed, err := uci.Parse([]byte(settings))
	require.NoError(t, err)
	config, err := model.Load(parsed)
	require.NoError(t, err)
	return config
}

// A rule only for some devices takes the connections of those devices to its lists, and the rule
// of block below it takes those of every other device, through each way this engine matches a
// rule set beside the source of a rule: a set of one rule (the own lists, a file of one rule of
// names and addresses), merged with the source; a set of several rules (a file of two rules, a
// list written as text), matched once the source matched (the way of the community lists). IPv6
// sources and destinations too. sing-box takes the configuration; a word among the devices it
// refuses.
func TestOnlyDevicesMatch(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, content string) string {
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
		return path
	}
	one := write("one.json", `{"version": 3, "rules": [{"domain_suffix": ["one.example"], "ip_cidr": ["100.71.64.0/24"]}]}`)
	two := write("two.json", `{"version": 3, "rules": [{"domain_suffix": ["two.example"]}, {"ip_cidr": ["100.71.62.0/24"]}]}`)
	text := write("text.lst", "text.example\n100.71.63.0/24\n")
	lists := "\toption user_domain_list_type 'dynamic'\n\tlist user_domains 'proxied.example'\n" +
		"\toption user_subnet_list_type 'dynamic'\n\tlist user_subnets '100.71.61.61/32'\n\tlist user_subnets '2001:2:0:61::61/128'\n" +
		"\tlist local_domain_lists '" + one + "'\n\tlist local_domain_lists '" + two + "'\n\tlist local_domain_lists '" + text + "'\n"
	settings := "config settings 'settings'\n\toption config_version '2'\n\toption dns_type 'udp'\n\toption dns_server '8.8.8.8'\n\toption ipv6_routing 'podkop'\n" +
		"\nconfig source 'own'\n\toption type 'links'\n\tlist link 'socks5://192.0.2.1:1080#Own'\n" +
		"\nconfig section 'tv'\n" + lists + "\tlist only_devices '192.168.78.10'\n\tlist only_devices '192.168.79.0/24'\n\tlist only_devices '2001:2:0:78::10'\n" +
		"\nconfig member\n\toption section 'tv'\n\toption role 'server'\n\toption source 'own'\n" +
		"\nconfig section 'others'\n" + lists +
		"\nconfig member\n\toption section 'others'\n\toption role 'server'\n\toption source 'block'\n"
	result, err := plan.Build(devicesSettings(t, settings), plan.Facts{IPv6: true}, plan.Options{RuleSetDir: dir, DecodeLink: DecodeLink, CheckList: CheckRuleSet})
	require.NoError(t, err)
	require.Empty(t, result.Warnings)
	for path, content := range result.Files {
		require.NoError(t, os.WriteFile(path, content, 0o644))
	}
	_, err = Check(result.Config)
	require.NoError(t, err)

	rules := routeRules(t, result.Config)
	for _, destination := range []string{"proxied.example", "100.71.61.61", "one.example", "100.71.64.5", "two.example", "100.71.62.5", "text.example", "100.71.63.5"} {
		require.Equal(t, "tv-out", routeOf(rules, "tproxy-in", "192.168.78.10", destination), destination)
		require.Equal(t, "tv-out", routeOf(rules, "tproxy-in", "192.168.79.200", destination), destination)
		require.Equal(t, "reject", routeOf(rules, "tproxy-in", "192.168.78.20", destination), destination)
		require.Equal(t, "reject", routeOf(rules, "tproxy-in", "192.168.80.10", destination), destination)
	}
	require.Equal(t, "tv-out", routeOf(rules, "tproxy-in6", "2001:2:0:78::10", "2001:2:0:61::61"))
	require.Equal(t, "reject", routeOf(rules, "tproxy-in6", "2001:2:0:78::20", "2001:2:0:61::61"))
	// the IPv4 address of the TV does not take its IPv6, nor the IPv6 one its IPv4
	require.Equal(t, "reject", routeOf(rules, "tproxy-in", "192.168.78.11", "proxied.example"))
	// what is in no list is in no rule
	for _, source := range []string{"192.168.78.10", "192.168.78.20"} {
		require.Equal(t, "final", routeOf(rules, "tproxy-in", source, "other.example"))
		require.Equal(t, "final", routeOf(rules, "tproxy-in", source, "100.71.65.5"))
	}

	// the resolve rule of the rule has the devices as well: sing-box takes it
	resolving := strings.Replace(settings, "\tlist only_devices '192.168.78.10'\n", "\toption resolve_real_ip_for_routing '1'\n\tlist only_devices '192.168.78.10'\n", 1)
	result, err = plan.Build(devicesSettings(t, resolving), plan.Facts{IPv6: true}, plan.Options{RuleSetDir: dir, DecodeLink: DecodeLink, CheckList: CheckRuleSet})
	require.NoError(t, err)
	require.Contains(t, string(result.Config), `"action": "resolve"`)
	_, err = Check(result.Config)
	require.NoError(t, err)

	// the control: the same rules without the field take every device
	unlimited := strings.ReplaceAll(settings, "\tlist only_devices '192.168.78.10'\n\tlist only_devices '192.168.79.0/24'\n\tlist only_devices '2001:2:0:78::10'\n", "")
	result, err = plan.Build(devicesSettings(t, unlimited), plan.Facts{IPv6: true}, plan.Options{RuleSetDir: dir, DecodeLink: DecodeLink, CheckList: CheckRuleSet})
	require.NoError(t, err)
	for path, content := range result.Files {
		require.NoError(t, os.WriteFile(path, content, 0o644))
	}
	rules = routeRules(t, result.Config)
	for _, destination := range []string{"proxied.example", "two.example", "100.71.63.5"} {
		require.Equal(t, "tv-out", routeOf(rules, "tproxy-in", "192.168.78.20", destination), destination)
	}

	// sing-box refuses a source that is no address: the check would tell it
	refused := strings.Replace(string(result.Config), `"outbound": "tv-out",`, `"outbound": "tv-out", "source_ip_cidr": ["word"],`, 1)
	require.NotEqual(t, string(result.Config), refused)
	_, err = Check([]byte(refused))
	require.Error(t, err)
}

// An enabled list with no item makes a file with no rule, which matches nothing. The file 0.8.20
// wrote for it, a rule of an empty list ({"domain_suffix": []}), which sing-box would take for a
// rule that matches every connection, matched nothing either: sing-box drops the empty values of a
// rule set as it reads the file, and a rule of nothing else with them.
func TestEmptyListMatchesNothing(t *testing.T) {
	dir := t.TempDir()
	settings := "config settings 'settings'\n\toption config_version '2'\n\toption dns_type 'udp'\n\toption dns_server '8.8.8.8'\n" +
		"\nconfig source 'own'\n\toption type 'links'\n\tlist link 'socks5://192.0.2.1:1080#Own'\n" +
		"\nconfig section 'tv'\n\toption user_domain_list_type 'dynamic'\n\tlist only_devices '192.168.78.10'\n" +
		"\nconfig member\n\toption section 'tv'\n\toption role 'server'\n\toption source 'own'\n"
	result, err := plan.Build(devicesSettings(t, settings), plan.Facts{}, plan.Options{RuleSetDir: dir, DecodeLink: DecodeLink, CheckList: CheckRuleSet})
	require.NoError(t, err)
	require.Len(t, result.Files, 1)
	for _, file := range []string{"", `{"version": 3, "rules": [{"domain_suffix": []}]}`} {
		for path, content := range result.Files {
			if file != "" {
				content = []byte(file)
			}
			require.NoError(t, os.WriteFile(path, content, 0o644))
		}
		_, err = Check(result.Config)
		require.NoError(t, err, file)
		rules := routeRules(t, result.Config)
		require.Equal(t, "final", routeOf(rules, "tproxy-in", "192.168.78.10", "other.example"), file)
		require.Equal(t, "final", routeOf(rules, "tproxy-in", "192.168.78.10", "100.71.65.5"), file)
	}
}
