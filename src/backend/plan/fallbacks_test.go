package plan

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const fallbackSources = "\nconfig source 'own'\n\toption type 'links'\n\tlist link 'vless://u@own.example:443#Own'\n" +
	"\nconfig source 'pair'\n\toption label 'pair'\n\toption type 'links'\n\tlist link 'vless://u@a.example:443#A'\n\tlist link 'vless://u@b.example:443#B'\n" +
	"\nconfig source 'trio'\n\toption label 'trio'\n\toption type 'links'\n\tlist link 'vless://u@c.example:443#C'\n\tlist link 'vless://u@d.example:443#D'\n\tlist link 'vless://u@e.example:443#E'\n" +
	"\nconfig source 'warp'\n\toption type 'interface'\n\toption interface 'awg0'\n" +
	"\nconfig source 'prov1'\n\toption type 'subscription'\n\toption url 'https://sub.example/x'\n"

// The fallbacks of a rule go in the order of their rows, unless the rule has a fallback choice:
// then the servers of all the rows are one URL test of that choice, and direct and block come after
// it, wherever they are among the rows.
func TestFallbackChoice(t *testing.T) {
	t.Parallel()
	rows := []string{row("server", "own"), row("fallback", "block"), row("fallback", "pair"), row("fallback", "direct"), row("fallback", "trio", "exclude D"), row("fallback", "warp")}
	pool := []string{"pair: A", "pair: B", "trio: C", "trio: E", "awg0"}
	for _, testCase := range []struct {
		name    string
		options []string
		mode    string
	}{
		{"fastest", []string{"fallback_choice fastest"}, ""},
		{"loss", []string{"fallback_choice loss"}, "loss"},
		{"balance", []string{"fallback_choice balance", "server_choice loss"}, "balance"},
	} {
		result, err := buildRules(t, fallbackSources+withOptions(ruleText("x", rows...), testCase.options...), nil)
		require.NoError(t, err, testCase.name)
		require.Empty(t, result.Warnings, testCase.name)
		_, outbounds := outboundsOf(t, result)
		test, group := outbounds["x-urltest-out"], outbounds["x-fallback-out"]
		require.Equal(t, []string{"x-fallback-out", "block", "direct-out"}, test.Fallbacks, testCase.name)
		require.Equal(t, "urltest", group.Type, testCase.name)
		require.Equal(t, pool, group.Outbounds, testCase.name)
		require.Empty(t, group.Fallbacks, testCase.name)
		require.Equal(t, testCase.mode, group.Mode, testCase.name)
		require.Equal(t, testCase.mode != "", group.LossURL != "", testCase.name)
		// the probes end with the use of the fallbacks
		idle := ""
		if testCase.mode != "" {
			idle = group.Interval
		}
		require.Equal(t, idle, group.IdleTimeout, testCase.name)
		require.Empty(t, test.IdleTimeout, testCase.name)
		for tag := range outbounds {
			require.False(t, strings.HasPrefix(tag, "x-fallback-") && tag != "x-fallback-out", "%s: %s", testCase.name, tag)
		}
		// the dashboard pins a server of the pool; the tag of the pool is told, and a hot swap takes it
		require.Equal(t, append([]string{"x-urltest-out", "Own"}, pool...), outbounds["x-out"].Outbounds, testCase.name)
		require.Equal(t, RuleTags{Name: "x", Selector: "x-out", Test: "x-urltest-out", Pool: "x-fallback-out"}, result.Tags.Rules["x"], testCase.name)
		require.Equal(t, TagOf{Rule: "x"}, result.Tags.Outbounds["x-fallback-out"], testCase.name)
		require.True(t, result.Swappable["x-fallback-out"], testCase.name)
	}
	// the mode of the pool is its own, not that of the servers of the rule
	result, err := buildRules(t, fallbackSources+withOptions(ruleText("x", rows...), "fallback_choice fastest", "server_choice balance"), nil)
	require.NoError(t, err)
	_, outbounds := outboundsOf(t, result)
	require.Equal(t, "balance", outbounds["x-urltest-out"].Mode)
	require.Empty(t, outbounds["x-fallback-out"].Mode)
}

// Without a fallback choice, with "order" and with a choice podkop does not know, the fallbacks are
// in the order of their rows; the unknown one warns.
func TestFallbacksInOrder(t *testing.T) {
	t.Parallel()
	rows := []string{row("server", "own"), row("fallback", "pair"), row("fallback", "direct"), row("fallback", "trio"), row("fallback", "own")}
	plain, err := buildRules(t, fallbackSources+ruleText("x", rows...), nil)
	require.NoError(t, err)
	_, outbounds := outboundsOf(t, plain)
	require.Equal(t, []string{"x-fallback-1-out", "direct-out", "x-fallback-3-out"}, outbounds["x-urltest-out"].Fallbacks)
	require.Empty(t, plain.Tags.Rules["x"].Pool)
	for _, choice := range []string{"order", "random"} {
		result, err := buildRules(t, fallbackSources+withOptions(ruleText("x", rows...), "fallback_choice "+choice), nil)
		require.NoError(t, err)
		require.Equal(t, string(plain.Config), string(result.Config), choice)
		if choice == "order" {
			require.Empty(t, result.Warnings)
			continue
		}
		require.Equal(t, []string{"rule x: the fallback choice \"random\" is not known: the fallbacks are used in their order"}, result.Warnings)
	}
}

// A server of the rule or one two rows take is in the pool once, or not at all; a pool of one server
// is the server, one of none is nothing; a subscription not downloaded yet brings none for now.
func TestFallbackPoolOfFew(t *testing.T) {
	t.Parallel()
	choice := "fallback_choice loss"
	result, err := buildRules(t, fallbackSources+
		withOptions(ruleText("repeated", row("server", "pair", "include A"), row("fallback", "pair"), row("fallback", "trio"), row("fallback", "trio", "include C")), choice)+
		withOptions(ruleText("one", row("server", "own"), row("fallback", "direct"), row("fallback", "pair", "include B"), row("fallback", "own")), choice)+
		withOptions(ruleText("none", row("server", "own"), row("fallback", "block"), row("fallback", "own"), row("fallback", "direct")), choice)+
		withOptions(ruleText("later", row("server", "own"), row("fallback", "prov1")), choice)+
		withOptions(ruleText("only", row("fallback", "pair")), choice), nil)
	require.NoError(t, err)
	_, outbounds := outboundsOf(t, result)
	require.Equal(t, []string{"pair: B", "trio: C", "trio: D", "trio: E"}, outbounds["repeated-fallback-out"].Outbounds)
	require.Equal(t, []string{"pair: B", "direct-out"}, outbounds["one-urltest-out"].Fallbacks)
	require.Equal(t, []string{"block", "direct-out"}, outbounds["none-urltest-out"].Fallbacks)
	require.Empty(t, outbounds["later-urltest-out"].Fallbacks)
	require.Empty(t, outbounds["only-urltest-out"].Outbounds)
	require.Equal(t, []string{"only-fallback-out"}, outbounds["only-urltest-out"].Fallbacks)
	for _, rule := range []string{"one", "none", "later"} {
		_, found := outbounds[rule+"-fallback-out"]
		require.False(t, found, rule)
		require.Empty(t, result.Tags.Rules[rule].Pool, rule)
	}
}

// A source named as the pool of a rule yields its tag to it, as to the other tags of a rule; without
// the choice the source keeps its name.
func TestFallbackPoolTag(t *testing.T) {
	t.Parallel()
	sources := fallbackSources + "\nconfig source 'odd'\n\toption label 'x-fallback-out'\n\toption type 'interface'\n\toption interface 'awg1'\n"
	rule := ruleText("x", row("server", "odd"), row("fallback", "pair"))
	result, err := buildRules(t, sources+withOptions(rule, "fallback_choice fastest"), nil)
	require.NoError(t, err)
	require.Equal(t, "x-fallback-out", result.Tags.Rules["x"].Pool)
	_, outbounds := outboundsOf(t, result)
	require.Equal(t, []string{"pair: A", "pair: B"}, outbounds["x-fallback-out"].Outbounds)
	require.Equal(t, []string{"x-fallback-out #2"}, outbounds["x-urltest-out"].Outbounds)
	result, err = buildRules(t, sources+rule, nil)
	require.NoError(t, err)
	_, outbounds = outboundsOf(t, result)
	require.Equal(t, "awg1", outbounds["x-fallback-out"].BindInterface)
}
