package ctl

import (
	"strconv"
	"strings"
	"time"

	"github.com/podkop-net/podkop-experimental/src/backend/api"
)

// subscriptionLines tell what is known of each subscription, a line each: its servers, when
// a download last brought its list and by which way, when its servers last changed, and what
// the provider tells of it (the traffic, the end); or why no list came.
func subscriptionLines(states []api.SubscriptionState, now time.Time) []string {
	var lines []string
	for _, state := range states {
		line := state.Name + ": "
		switch {
		case state.Changed == nil && state.Error != "":
			line = "❌ " + line + "no list: " + state.Error
		case state.Changed == nil:
			line = "⏳ " + line + "the list is not downloaded yet"
		default:
			line += strconv.Itoa(state.Servers) + " servers, " + strconv.Itoa(state.Usable) + " can be used"
			// the way is that of the last list: of the last check, or of the list kept on flash
			way := ""
			if state.Route != "" {
				way = " (" + state.Route + ")"
			}
			if state.Checked != nil {
				line += "; checked " + takenAgo(now.Sub(*state.Checked)) + way + "; servers changed " + takenAgo(now.Sub(*state.Changed))
			} else {
				line += "; servers changed " + takenAgo(now.Sub(*state.Changed)) + way + "; not checked since the start"
			}
			if state.Error != "" {
				line = "⚠️ " + line + "; the last download failed: " + state.Error
			} else {
				line = "✅ " + line
			}
		}
		if told := providerLine(state.Provider, now); told != "" {
			line += "; " + told
		}
		lines = append(lines, line)
	}
	return lines
}

// providerLine tells what the provider told of a subscription, as `"My VPN", traffic 12.5 GiB
// of 100 GiB, until 2026-12-31 (64 days)`.
func providerLine(info *api.ProviderInfo, now time.Time) string {
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

// loadAndWait downloads a list to be shown as a job of the backend, and waits for it: the
// command line has no limit of LuCI.
func loadAndWait(client api.Client, address string) *api.SubscriptionPreview {
	job, err := client.StartLoad(address)
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
