package ctl

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/podkop-net/podkop-experimental/src/backend/model"
	"github.com/podkop-net/podkop-experimental/src/backend/plan"
)

// choiceProxy is an outbound as the Clash API lists it, with what the server choice of the
// engine (urltest modes) adds: the loss probes of a server, the mode and the balance of a group.
type choiceProxy struct {
	Type      string   `json:"type"`
	Now       string   `json:"now"`
	All       []string `json:"all"`
	Fallbacks []string `json:"fallbacks"`
	History   []struct {
		Delay int `json:"delay"`
	} `json:"history"`
	Mode    string `json:"mode"`
	Balance []struct {
		Name    string `json:"name"`
		Devices int    `json:"devices"`
	} `json:"balance"`
	Loss *struct {
		Windows    []choiceWindow `json:"windows"`
		RTT        int            `json:"rtt"`
		NotCounted string         `json:"not_counted"`
	} `json:"loss"`
}

// choiceWindow is what the loss probes of a server counted over the last hours.
type choiceWindow struct {
	Hours    int `json:"hours"`
	Probes   int `json:"probes"`
	Segments int `json:"segments"`
	Lost     int `json:"lost"`
}

// choiceSegment is the size of a segment the traffic of the probes is told by: the wire bytes of
// a probe are its segments, of Ethernet with TCP timestamps.
const choiceSegment = 1448

// choiceLines tells what the server choice of the rules that choose avoiding loss or balance has
// counted, for a report: the loss of their servers over the windows the engine keeps (1, 6 and
// 24 hours, with the probes), the least RTT, a server whose probe could not count, the servers of
// a balance with the devices each carries, and the traffic of the probes over the last day. Nothing
// when no rule chooses so.
func choiceLines(caller *clashCaller, config *model.Config) []string {
	names := config.Names()
	var choosing []*model.Section
	for index := range config.Sections {
		section := &config.Sections[index]
		if section.Enabled && (section.Choice == model.ChoiceLoss || section.Choice == model.ChoiceBalance) && config.HasOutbound(section) {
			choosing = append(choosing, section)
		}
	}
	if len(choosing) == 0 {
		return nil
	}
	_, content := caller.call(http.MethodGet, "/proxies", "", 10*time.Second)
	var listed struct {
		Proxies map[string]choiceProxy `json:"proxies"`
	}
	if json.Unmarshal(content, &listed) != nil || len(listed.Proxies) == 0 {
		return []string{"❌ The server choice could not be read: the Clash API of podkop does not answer"}
	}
	tags := caller.tags()
	var lines []string
	// a server two rules take is probed once: its traffic counts once
	probed := make(map[string]choiceProxy)
	for _, section := range choosing {
		outbounds := plan.RuleTags{Name: names.Rule(section.Name), Test: ruleTest(plan.RuleTags{Selector: plan.RuleOutbound(config, section.Name)})}
		if tags != nil {
			outbounds = tags.Rules[section.Name]
		}
		group, found := listed.Proxies[outbounds.Test]
		if outbounds.Test == "" || !found {
			lines = append(lines, "ℹ️ "+outbounds.Name+": one server, nothing to choose from")
			continue
		}
		want := "avoiding loss"
		if section.Choice == model.ChoiceBalance {
			want = "balance"
		}
		switch {
		case group.Mode == "":
			lines = append(lines, "⚠️ "+outbounds.Name+": "+want+" is set, the engine chooses the fastest (an engine before urltest modes?)")
		case group.Mode != section.Choice:
			lines = append(lines, "⚠️ "+outbounds.Name+": "+want+" is set, the engine chooses by "+group.Mode)
		case section.Choice == model.ChoiceBalance:
			members := make([]string, 0, len(group.Balance))
			for _, member := range group.Balance {
				members = append(members, fmt.Sprintf("%s (%d devices)", member.Name, member.Devices))
			}
			if len(members) == 0 {
				lines = append(lines, "⚠️ "+outbounds.Name+": balance, but no server is in it now: the connections go by the fastest, "+group.Now)
			} else {
				lines = append(lines, "🎯 "+outbounds.Name+": balance over "+strings.Join(members, ", "))
			}
		default:
			lines = append(lines, "🎯 "+outbounds.Name+": avoiding loss, now "+group.Now)
		}
		for _, tag := range group.All[:max(len(group.All)-len(group.Fallbacks), 0)] {
			server := listed.Proxies[tag]
			lines = append(lines, "\t"+serverChoiceLine(tag, server))
			if server.Loss != nil {
				probed[tag] = server
			}
		}
	}
	probes, segments := 0, 0
	for _, server := range probed {
		if day := lossWindow(server, 24); day != nil {
			probes += day.Probes
			segments += day.Segments
		}
	}
	lines = append(lines, fmt.Sprintf("📶 Loss probes of the last 24 hours: %d, about %.1f MB", probes, float64(segments)*choiceSegment/1e6))
	return lines
}

// lossWindow is the window of hours of a server, nil without one.
func lossWindow(server choiceProxy, hours int) *choiceWindow {
	if server.Loss == nil {
		return nil
	}
	for index := range server.Loss.Windows {
		if server.Loss.Windows[index].Hours == hours {
			return &server.Loss.Windows[index]
		}
	}
	return nil
}

// serverChoiceLine is a server of a rule that chooses avoiding loss or balance: its delay, its
// loss over 1, 6 and 24 hours, its RTT.
func serverChoiceLine(tag string, server choiceProxy) string {
	parts := []string{tag + ":"}
	if len(server.History) > 0 && server.History[0].Delay > 0 {
		parts = append(parts, fmt.Sprintf("delay %d ms,", server.History[0].Delay))
	} else {
		parts = append(parts, "no delay (down),")
	}
	switch {
	case server.Loss == nil:
		parts = append(parts, "no loss probe yet")
	case server.Loss.NotCounted != "" && lossWindow(server, 24) == nil:
		parts = append(parts, "its probe could not count (a multiplexed transport or QUIC): chosen by its delay")
	default:
		var windows []string
		for _, hours := range []int{1, 6, 24} {
			window := lossWindow(server, hours)
			if window == nil || window.Segments == 0 {
				windows = append(windows, fmt.Sprintf("%d h —", hours))
				continue
			}
			windows = append(windows, fmt.Sprintf("%d h %.2f%% (%d of %d, %d probes)", hours, float64(window.Lost)*100/float64(window.Segments), window.Lost, window.Segments, window.Probes))
		}
		parts = append(parts, "loss "+strings.Join(windows, ", "))
		if server.Loss.RTT > 0 {
			parts = append(parts, fmt.Sprintf("RTT %d ms", server.Loss.RTT))
		}
		if server.Loss.NotCounted != "" {
			parts = append(parts, "(the last probe could not count)")
		}
	}
	return strings.Join(parts, " ")
}
