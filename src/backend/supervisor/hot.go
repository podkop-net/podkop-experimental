package supervisor

import (
	"bytes"
	"encoding/json"
	"errors"
	"time"

	"github.com/podkop-net/podkop-experimental/src/backend/engine"
	"github.com/podkop-net/podkop-experimental/src/backend/plan"
)

// A configuration that differs from the one that runs only by the servers of the
// subscriptions, the URL tests of their groups and the selectors of the sections of the type
// group (plan.Result.Swappable) is applied without a new sing-box: the outbounds of the tags
// that changed are replaced while it runs (engine.Instance.Swap), and the connections that
// are open keep the outbounds they have. Anything else, or a replacement that fails, starts
// the configuration as before.

// minKept is how many servers of the changes before sing-box may keep for their connections at
// least; as many as the configuration has outbounds to replace when that is more. Beyond, the
// configuration is started anew, which lets them all go.
const minKept = 64

// hotSwap is a configuration sing-box takes while it runs: what to replace, and how much of it.
type hotSwap struct {
	swap                    engine.Swap
	added, changed, removed int
}

// hotPlan finds the outbounds to replace for the next configuration to run instead of the
// current one; nil, with why, when it cannot be applied so.
func hotPlan(current *plan.Result, next *plan.Result) (*hotSwap, string) {
	var before, after map[string]json.RawMessage
	if json.Unmarshal(current.Config, &before) != nil || json.Unmarshal(next.Config, &after) != nil {
		return nil, "the configuration cannot be read"
	}
	for key := range merged(before, after) {
		if key != "outbounds" && !bytes.Equal(before[key], after[key]) {
			return nil, "its " + key + " changed"
		}
	}
	oldOrder, oldByTag, err := outboundsOf(before["outbounds"])
	if err != nil {
		return nil, "the outbounds cannot be read"
	}
	newOrder, newByTag, err := outboundsOf(after["outbounds"])
	if err != nil {
		return nil, "the outbounds cannot be read"
	}
	hot := &hotSwap{}
	// the tags that change or go: nothing that stays may go through one of them
	moved := make(map[string]bool)
	gone := make(map[string]bool)
	for _, tag := range newOrder {
		content := newByTag[tag]
		previous, existed := oldByTag[tag]
		switch {
		case !existed:
			hot.added++
		case !bytes.Equal(previous, content):
			hot.changed++
			moved[tag] = true
			if !current.Swappable[tag] {
				return nil, "outbound " + tag + " changed"
			}
		default:
			continue
		}
		if !next.Swappable[tag] {
			return nil, "outbound " + tag + " changed"
		}
		hot.swap.Put = append(hot.swap.Put, content)
	}
	for _, tag := range oldOrder {
		if _, kept := newByTag[tag]; kept {
			continue
		}
		if !current.Swappable[tag] {
			return nil, "outbound " + tag + " is gone"
		}
		hot.removed++
		moved[tag], gone[tag] = true, true
		hot.swap.Remove = append(hot.swap.Remove, tag)
	}
	if len(hot.swap.Put)+len(hot.swap.Remove) == 0 {
		return nil, "only the order of the outbounds changed"
	}
	// What stays the same but goes through what changes is replaced too, when sing-box may
	// replace it: a group and a selector name their members by tag, and do not change when a
	// member changes under its tag. What sing-box may not replace needs a new sing-box: it keeps
	// the outbound it found at its start.
	for grew := true; grew; {
		grew = false
		for _, tag := range newOrder {
			if previous, existed := oldByTag[tag]; !existed || !bytes.Equal(previous, newByTag[tag]) || moved[tag] {
				// built anew already
				continue
			}
			for _, reference := range outboundReferences(newByTag[tag]) {
				if !moved[reference] {
					continue
				}
				if !current.Swappable[tag] || !next.Swappable[tag] {
					return nil, "outbound " + tag + " goes through " + reference + ", which changes"
				}
				hot.swap.Put = append(hot.swap.Put, newByTag[tag])
				hot.changed++
				moved[tag], grew = true, true
				break
			}
		}
	}
	// A DNS server and the HTTP client of the lists find the outbound of their detour at every
	// dial (podkop-engine r19); what else has one may keep the outbound it found at its start.
	// Nothing may name an outbound that goes.
	for key, content := range after {
		if key == "outbounds" {
			continue
		}
		if key != "dns" && key != "http_clients" {
			if reference := referenceTo(content, detourKeys, moved); reference != "" {
				return nil, "outbound " + reference + " changes, and the " + key + " of the configuration go through it"
			}
		}
		if reference := referenceTo(content, outboundKeys, gone); reference != "" {
			return nil, "outbound " + reference + " goes, and the " + key + " of the configuration name it"
		}
	}
	return hot, ""
}

var (
	detourKeys   = map[string]bool{"detour": true, "download_detour": true}
	outboundKeys = map[string]bool{"detour": true, "download_detour": true, "outbound": true, "final": true}
)

func merged(left map[string]json.RawMessage, right map[string]json.RawMessage) map[string]bool {
	keys := make(map[string]bool, len(left)+len(right))
	for key := range left {
		keys[key] = true
	}
	for key := range right {
		keys[key] = true
	}
	return keys
}

// outboundsOf reads the outbounds of a configuration by tag, in their order.
func outboundsOf(content json.RawMessage) ([]string, map[string]json.RawMessage, error) {
	var outbounds []json.RawMessage
	if len(content) > 0 {
		err := json.Unmarshal(content, &outbounds)
		if err != nil {
			return nil, nil, err
		}
	}
	order := make([]string, 0, len(outbounds))
	byTag := make(map[string]json.RawMessage, len(outbounds))
	for _, outbound := range outbounds {
		var head struct {
			Tag string `json:"tag"`
		}
		err := json.Unmarshal(outbound, &head)
		if err != nil {
			return nil, nil, err
		}
		order = append(order, head.Tag)
		byTag[head.Tag] = outbound
	}
	return order, byTag, nil
}

// outboundReferences are the tags an outbound goes through: the members and the fallbacks of a
// group, its default, the outbound it dials through.
func outboundReferences(content json.RawMessage) []string {
	var fields struct {
		Outbounds []string `json:"outbounds"`
		Fallbacks []string `json:"fallbacks"`
		Default   string   `json:"default"`
		Detour    string   `json:"detour"`
	}
	if json.Unmarshal(content, &fields) != nil {
		return nil
	}
	return append(append(fields.Outbounds, fields.Fallbacks...), fields.Default, fields.Detour)
}

// referenceTo finds in a part of the configuration a value of one of the keys that is one of the
// tags.
func referenceTo(content json.RawMessage, keys map[string]bool, tags map[string]bool) string {
	var value any
	if json.Unmarshal(content, &value) != nil {
		return ""
	}
	var walk func(value any) string
	walk = func(value any) string {
		switch typed := value.(type) {
		case map[string]any:
			for key, item := range typed {
				if text, isText := item.(string); isText && keys[key] && tags[text] {
					return text
				}
				if found := walk(item); found != "" {
					return found
				}
			}
		case []any:
			for _, item := range typed {
				if found := walk(item); found != "" {
					return found
				}
			}
		}
		return ""
	}
	return walk(value)
}

// swap applies the next configuration by replacing the outbounds of the hot swap in the
// instance that runs. It tells false when sing-box did not take them: nothing changed then,
// and the caller starts the configuration anew.
func (s *Supervisor) swap(current *running, next *candidate, started time.Time) (Result, bool) {
	limit := max(minKept, len(next.result.Swappable))
	swapped, err := current.instance.Swap(next.result.Config, next.hot.swap, limit)
	if err != nil {
		if errors.Is(err, engine.ErrTooManyKept) {
			s.log("info", "sing-box keeps more than ", limit, " servers replaced in the last minutes (each is closed 2 minutes after the change at the earliest, later while a connection uses it): the configuration is checked to start anew")
		} else {
			s.log("warn", "sing-box did not take the new servers of the groups while it runs (", err, "): the configuration is checked to start anew")
		}
		return Result{}, false
	}
	previousFirewall := current.firewall
	err = s.writeFiles(next.result, current.result)
	if err != nil {
		s.log("error", err)
	}
	s.storeConfig(next)
	s.current = &running{settings: next.settings, result: next.result, instance: current.instance}
	err = s.surround(previousFirewall)
	if err != nil {
		s.log("error", err)
	}
	took := time.Since(started).Milliseconds()
	s.log("info", "the settings are applied in ", took, " ms: the servers of the groups are replaced (", next.hot.added, " new outbounds, ",
		next.hot.changed, " rebuilt, ", next.hot.removed, " taken out; ", swapped.Kept, " replaced ones kept while connections may use them), sing-box keeps running")
	return s.done(true, false, "applied in ", took, " ms, sing-box keeps running"), true
}
