package ctl

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/podkop-net/podkop-experimental/src/backend/api"
	"github.com/podkop-net/podkop-experimental/src/backend/model"
	"github.com/podkop-net/podkop-experimental/src/backend/subscription"
)

// subscriptionLines tell what is known of each subscription, a line each: its servers, when
// a download last brought its list and by which way, when its servers last changed, and what
// the provider tells of it (the traffic, the end); or why no list came. A subscription is
// called by its name, with its section when that differs (model.Names).
func subscriptionLines(states []api.SubscriptionState, names model.Names, now time.Time) []string {
	var lines []string
	for _, state := range states {
		line := names.SourceText(state.Name) + ": "
		switch {
		case state.Changed == nil && state.Error != "":
			line = "❌ " + line + "no list: " + state.Error
		case state.Changed == nil:
			line = "⏳ " + line + "the list is not downloaded yet"
		default:
			line += strconv.Itoa(state.Servers) + " servers, " + strconv.Itoa(state.Usable) + " can be used"
			switch state.Format {
			case "xray":
				line += ", from Xray JSON"
			case "sing-box":
				line += ", from sing-box JSON"
			}
			// the way is that of the last list: of the last check, or of the list kept on flash
			way := ""
			if state.Route != "" {
				way = " (" + state.Route + ")"
			}
			if state.Checked != nil {
				line += "; checked " + takenAgo(now.Sub(*state.Checked)) + way + "; servers changed " + takenAgo(now.Sub(*state.Changed))
				if changes := state.Changes; changes != nil {
					line += " (renamed " + strconv.Itoa(changes.Renamed) + ", changed " + strconv.Itoa(changes.Changed) + fieldsOf(changes.Fields) +
						", removed " + strconv.Itoa(changes.Removed) + ", added " + strconv.Itoa(changes.Added) + ")"
				}
			} else {
				line += "; servers changed " + takenAgo(now.Sub(*state.Changed)) + way + "; not checked since the start"
			}
			if state.Error != "" {
				line = "⚠️ " + line + "; the last download failed: " + state.Error
			} else {
				line = "✅ " + line
			}
		}
		if state.Busy {
			line += "; downloading now"
		}
		if told := providerLine(state.Provider, now); told != "" {
			line += "; " + told
		}
		lines = append(lines, line+requestLine(state))
	}
	return lines
}

// requestLine tells what the settings add to the request of a subscription: the preset and the
// User-Agent (the name of an app, no secret), the names of the extra headers (never their
// values), and the lines left out: "; asked as Happ (Happ/4.8.3/Linux)", "; User-Agent INCY;
// headers Authorization; left out: header 2 (X-Hwid)".
func requestLine(state api.SubscriptionState) string {
	line := ""
	if asked := subscription.AskedAs(state.Preset, state.Agent); asked != "" {
		line += "; " + asked
	}
	if len(state.Headers) > 0 {
		line += "; headers " + strings.Join(state.Headers, ", ")
	}
	var left []string
	for _, problem := range state.Problems {
		switch {
		case problem.Line == 0 && problem.Code == "preset":
			left = append(left, "the preset of the User-Agent")
		case problem.Line == 0:
			left = append(left, "the User-Agent")
		case problem.Name != "":
			left = append(left, "header "+strconv.Itoa(problem.Line)+" ("+problem.Name+")")
		default:
			left = append(left, "header "+strconv.Itoa(problem.Line))
		}
	}
	if len(left) > 0 {
		line += "; left out of the request: " + strings.Join(left, ", ")
	}
	return line
}

// fieldsOf names the options of the servers that changed: " (tls.server_name, server_port)".
func fieldsOf(fields []string) string {
	if len(fields) == 0 {
		return ""
	}
	return ": " + strings.Join(fields, ", ")
}

// providerLine tells what the provider told of a subscription, as `"My VPN", traffic 12.5 GiB
// of 100 GiB, until 2026-12-31 (64 days)`.
func providerLine(info *subscription.ProviderInfo, now time.Time) string {
	if info == nil {
		return ""
	}
	var parts []string
	if info.Title != "" {
		parts = append(parts, strconv.Quote(info.Title))
	}
	if info.Traffic {
		used := info.Upload + info.Download
		if info.Total > 0 {
			parts = append(parts, "traffic "+bytesText(used)+" of "+bytesText(info.Total))
		} else {
			parts = append(parts, "traffic "+bytesText(used)+", no limit")
		}
	}
	if info.Expire != nil {
		day := info.Expire.Local().Format("2006-01-02")
		if left := info.Expire.Sub(now); left > 0 {
			parts = append(parts, "until "+day+" ("+ago(left)+")")
		} else {
			parts = append(parts, "ended "+day)
		}
	}
	return strings.Join(parts, ", ")
}

// bytesText writes an amount of bytes in MiB, GiB or TiB.
func bytesText(amount int64) string {
	const mib, gib, tib = 1 << 20, 1 << 30, 1 << 40
	switch {
	case amount >= tib:
		return strconv.FormatFloat(float64(amount)/tib, 'f', 2, 64) + " TiB"
	case amount >= gib:
		return strconv.FormatFloat(float64(amount)/gib, 'f', 1, 64) + " GiB"
	default:
		return strconv.FormatFloat(float64(amount)/mib, 'f', 0, 64) + " MiB"
	}
}

// takenAgo tells how long ago a list was taken, roughly.
func takenAgo(passed time.Duration) string {
	if passed < time.Minute {
		return "just now"
	}
	return ago(passed) + " ago"
}

// listRequest is the request a download of a list for the page is asked with: the JSON after
// the address ({user_agent_preset, user_agent, headers}), none when there is nothing after it.
// It tells false for what is not that JSON.
func listRequest(arguments []string) (api.ListRequest, bool) {
	var request api.ListRequest
	if len(arguments) < 3 || strings.TrimSpace(arguments[2]) == "" {
		return request, true
	}
	return request, json.Unmarshal([]byte(arguments[2]), &request) == nil
}

// loadAndWait downloads a list to be shown as a job of the backend, and waits for it: the
// command line has no limit of LuCI.
func loadAndWait(client api.Client, address string, request api.ListRequest) *api.SubscriptionPreview {
	job, err := client.StartLoad(address, request)
	if err != nil {
		return notRunning()
	}
	deadline := time.Now().Add(2 * time.Minute)
	for job.State == "running" && job.ID != "" && time.Now().Before(deadline) {
		time.Sleep(500 * time.Millisecond)
		next, err := client.LoadState(job.ID)
		if err != nil {
			return notRunning()
		}
		job = next
	}
	if job.Preview == nil {
		return &api.SubscriptionPreview{Servers: []api.PreviewServer{}, Error: "the download did not end in time", ErrorCode: "timeout"}
	}
	return job.Preview
}

// notRunning is the preview when there is no backend to download a list.
func notRunning() *api.SubscriptionPreview {
	return &api.SubscriptionPreview{Servers: []api.PreviewServer{}, Error: "podkop does not run: a subscription is downloaded by its backend", ErrorCode: "notrunning"}
}
