package ctl

import (
	"encoding/json"
	"testing"

	"github.com/podkop-net/podkop-experimental/src/backend/model"
	"github.com/podkop-net/podkop-experimental/src/backend/plan"

	"github.com/stretchr/testify/require"
)

func windows(lost ...int) map[string]any {
	list := make([]map[string]any, 0, 5)
	for index, hours := range []int{1, 3, 6, 12, 24} {
		list = append(list, map[string]any{"hours": hours, "probes": 2 * (index + 1), "segments": 400 * (index + 1), "lost": lost[index]})
	}
	return map[string]any{"windows": list, "rtt": 42}
}

// The server choice of the rules that choose avoiding loss or balance, for a report: the loss
// of their servers by the windows, the balance with its devices, a server whose probe could
// not count, a group the engine runs otherwise, and the traffic of the probes, once a server.
func TestChoiceLines(t *testing.T) {
	proxies := map[string]map[string]any{
		"av-out":          {"type": "Selector", "now": "av-urltest-out"},
		"av-urltest-out":  {"type": "URLTest", "now": "s-b", "mode": "loss", "all": []string{"s-a", "s-b", "s-g", "av-fallback-1-out"}, "fallbacks": []string{"av-fallback-1-out"}},
		"bl-out":          {"type": "Selector", "now": "bl-urltest-out"},
		"bl-urltest-out":  {"type": "URLTest", "now": "s-a", "mode": "balance", "all": []string{"s-a", "s-b"}, "balance": []map[string]any{{"name": "s-a", "devices": 2}, {"name": "s-b", "devices": 1}}},
		"old-out":         {"type": "Selector", "now": "old-urltest-out"},
		"old-urltest-out": {"type": "URLTest", "now": "s-a", "all": []string{"s-a", "s-b"}},
		"s-a":             {"type": "VLESS", "history": []map[string]any{{"delay": 80}}, "loss": windows(0, 2, 6, 12, 30)},
		"s-b":             {"type": "VLESS", "history": []map[string]any{{"delay": 120}}, "loss": windows(0, 0, 0, 0, 0)},
		"s-g":             {"type": "VLESS", "history": []map[string]any{{"delay": 90}}, "loss": map[string]any{"not_counted": "2026-11-06T06:00:00Z"}},
	}
	caller := outboundsCaller(t, proxies, nil)
	rows := []model.Member{{Source: "src"}}
	config := &model.Config{Sources: []model.Source{{Name: "src", Type: "links", Links: []string{"vless://x"}}}}
	config.Sections = []model.Section{
		{Name: "fast", Enabled: true, Servers: rows, Choice: model.ChoiceFastest},
		{Name: "av", Enabled: true, Servers: rows, Choice: model.ChoiceLoss},
		{Name: "bl", Enabled: true, Servers: rows, Choice: model.ChoiceBalance},
		{Name: "old", Enabled: true, Servers: rows, Choice: model.ChoiceLoss},
	}
	require.Equal(t, []string{
		"🎯 av: avoiding loss, now s-b",
		"\ts-a: delay 80 ms, loss 1 h 0.00% (0 of 400, 2 probes), 6 h 0.50% (6 of 1200, 6 probes), 24 h 1.50% (30 of 2000, 10 probes) RTT 42 ms",
		"\ts-b: delay 120 ms, loss 1 h 0.00% (0 of 400, 2 probes), 6 h 0.00% (0 of 1200, 6 probes), 24 h 0.00% (0 of 2000, 10 probes) RTT 42 ms",
		"\ts-g: delay 90 ms, its probe could not count (a multiplexed transport, or QUIC and a loss URL that serves no ranges): chosen by its delay",
		"🎯 bl: balance over s-a (2 devices), s-b (1 devices)",
		"\ts-a: delay 80 ms, loss 1 h 0.00% (0 of 400, 2 probes), 6 h 0.50% (6 of 1200, 6 probes), 24 h 1.50% (30 of 2000, 10 probes) RTT 42 ms",
		"\ts-b: delay 120 ms, loss 1 h 0.00% (0 of 400, 2 probes), 6 h 0.00% (0 of 1200, 6 probes), 24 h 0.00% (0 of 2000, 10 probes) RTT 42 ms",
		"⚠️ old: avoiding loss is set but not applied yet: Save & Apply",
		"\ts-a: delay 80 ms, loss 1 h 0.00% (0 of 400, 2 probes), 6 h 0.50% (6 of 1200, 6 probes), 24 h 1.50% (30 of 2000, 10 probes) RTT 42 ms",
		"\ts-b: delay 120 ms, loss 1 h 0.00% (0 of 400, 2 probes), 6 h 0.00% (0 of 1200, 6 probes), 24 h 0.00% (0 of 2000, 10 probes) RTT 42 ms",
		"📶 Loss probes of the last 24 hours: 20, about 5.8 MB",
	}, choiceLines(caller, config))
	config.Sections = config.Sections[:1]
	require.Nil(t, choiceLines(caller, config), "no rule chooses so: no section")
}

// The fallbacks of a rule that choose so too: their servers while the rule goes through them, one
// line while it does not (their loss is not probed then), a group that is not there, one the engine
// runs otherwise. The choice of the servers and that of the fallbacks are each on their own.
func TestChoiceLinesOfFallbacks(t *testing.T) {
	server := map[string]any{"type": "VLESS", "history": []map[string]any{{"delay": 80}}, "loss": windows(0, 0, 0, 0, 0)}
	proxies := map[string]map[string]any{
		"idle-out":          {"type": "Selector", "now": "idle-urltest-out"},
		"idle-urltest-out":  {"type": "URLTest", "now": "s-a", "all": []string{"s-a", "idle-fallback-out"}, "fallbacks": []string{"idle-fallback-out"}},
		"idle-fallback-out": {"type": "URLTest", "now": "s-b", "mode": "balance", "all": []string{"s-b", "s-c"}},
		"used-out":          {"type": "Selector", "now": "used-urltest-out"},
		"used-urltest-out":  {"type": "URLTest", "now": "used-fallback-out", "mode": "loss", "all": []string{"s-a", "used-fallback-out"}, "fallbacks": []string{"used-fallback-out"}},
		"used-fallback-out": {"type": "URLTest", "now": "s-b", "mode": "loss", "all": []string{"s-b", "s-c"}},
		"pin-out":           {"type": "Selector", "now": "s-c"},
		"pin-urltest-out":   {"type": "URLTest", "now": "pin-fallback-out", "all": []string{"s-a", "pin-fallback-out"}, "fallbacks": []string{"pin-fallback-out"}},
		"pin-fallback-out":  {"type": "URLTest", "now": "s-b", "mode": "loss", "all": []string{"s-b", "s-c"}},
		"old-out":           {"type": "Selector", "now": "old-urltest-out"},
		"old-urltest-out":   {"type": "URLTest", "now": "s-a", "all": []string{"s-a", "old-fallback-out"}, "fallbacks": []string{"old-fallback-out"}},
		"old-fallback-out":  {"type": "URLTest", "now": "s-b", "all": []string{"s-b", "s-c"}},
		"few-out":           {"type": "Selector", "now": "few-urltest-out"},
		"few-urltest-out":   {"type": "URLTest", "now": "s-a", "all": []string{"s-a", "s-b"}, "fallbacks": []string{"s-b"}},
		"s-a":               server,
		"s-b":               server,
		"s-c":               {"type": "VLESS", "history": []map[string]any{}},
	}
	rows := []model.Member{{Source: "src"}}
	config := &model.Config{Sources: []model.Source{{Name: "src", Type: "links", Links: []string{"vless://x"}}}}
	tags := &plan.Tags{Rules: make(map[string]plan.RuleTags)}
	add := func(name string, choice string, fallbackChoice string, pool string) {
		config.Sections = append(config.Sections, model.Section{Name: name, Enabled: true, Servers: rows, Fallbacks: rows, Choice: choice, FallbackChoice: fallbackChoice})
		tags.Rules[name] = plan.RuleTags{Name: name, Selector: name + "-out", Test: name + "-urltest-out", Pool: pool}
	}
	add("idle", model.ChoiceFastest, model.ChoiceBalance, "idle-fallback-out")
	add("used", model.ChoiceLoss, model.ChoiceLoss, "used-fallback-out")
	add("pin", model.ChoiceFastest, model.ChoiceLoss, "pin-fallback-out")
	add("old", model.ChoiceFastest, model.ChoiceLoss, "old-fallback-out")
	add("few", model.ChoiceFastest, model.ChoiceBalance, "")
	add("order", model.ChoiceFastest, model.ChoiceOrder, "")
	add("fast", model.ChoiceFastest, model.ChoiceFastest, "fast-fallback-out")
	caller := outboundsCaller(t, proxies, nil)
	caller.ask()
	content, err := json.Marshal(tags)
	require.NoError(t, err)
	caller.facts.Tags = content
	line := ": delay 80 ms, loss 1 h 0.00% (0 of 400, 2 probes), 6 h 0.00% (0 of 1200, 6 probes), 24 h 0.00% (0 of 2000, 10 probes) RTT 42 ms"
	require.Equal(t, []string{
		"ℹ️ idle, its fallbacks: balance among 2 servers, not in use now: their loss is not probed",
		"🎯 used: avoiding loss, now used-fallback-out",
		"\ts-a" + line,
		"🎯 used, its fallbacks: avoiding loss, now s-b",
		"\ts-b" + line,
		"\ts-c: no delay (down), no loss probe yet",
		"ℹ️ pin, its fallbacks: avoiding loss among 2 servers, not in use now: their loss is not probed",
		"⚠️ old, its fallbacks: avoiding loss is set but not applied yet: Save & Apply",
		"\ts-b" + line,
		"\ts-c: no delay (down), no loss probe yet",
		"ℹ️ few, its fallbacks: one server or none, or not applied yet: nothing to choose from",
		"📶 Loss probes of the last 24 hours: 20, about 5.8 MB",
	}, choiceLines(caller, config))
}
