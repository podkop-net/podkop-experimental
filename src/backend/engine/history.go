package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing/service"
)

// history is the urltest history of the process: what the URL tests of the groups found,
// by the tag of the outbound. sing-box makes one an instance unless its context has one,
// and a group of a configuration that replaced another then took its first member until
// its own first test, though the members had been tested a minute before. With one
// history the group chooses at once, and its first test round passes
// over the members tested within the interval, as it would have in the instance before.
//
// A result belongs to the outbound it was found for, not to its tag: the tag of a section
// keeps its name when the link of the section changes. The results of the outbounds that
// changed are forgotten at the start of the next configuration (forgetChanged), or a group
// would take the delay of the server a tag had before for the one it has now, and would
// not test that one for an interval.
var history = &sharedHistory{storage: urltest.NewHistoryStorage()}

type sharedHistory struct {
	storage *urltest.HistoryStorage
	access  sync.Mutex
	// started are the dialers of the configuration started last; nil before the first
	started map[string]dialer
}

// dialer is an outbound or an endpoint of a configuration as the history sees it.
type dialer struct {
	// content is the JSON object as the configuration has it
	content []byte
	// detour is the tag of the outbound it dials through, if any
	detour string
}

// withHistory gives a context the history of the process.
func withHistory(ctx context.Context) context.Context {
	return service.ContextWithPtr(ctx, history.storage)
}

// dialersOf reads the outbounds and the endpoints of a configuration by tag. A
// configuration that cannot be read has none: every result is forgotten then.
func dialersOf(configuration []byte) map[string]dialer {
	var parsed struct {
		Outbounds []json.RawMessage `json:"outbounds"`
		Endpoints []json.RawMessage `json:"endpoints"`
	}
	result := make(map[string]dialer)
	if json.Unmarshal(configuration, &parsed) != nil {
		return result
	}
	for _, content := range append(parsed.Outbounds, parsed.Endpoints...) {
		var head struct {
			Tag    string `json:"tag"`
			Detour string `json:"detour"`
		}
		if json.Unmarshal(content, &head) != nil || head.Tag == "" {
			continue
		}
		result[head.Tag] = dialer{content: content, detour: head.Detour}
	}
	return result
}

// forgetting is what forgetChanged did: the tags it forgot and the results they had, and the
// tags it gave the result of the tag they had before.
type forgetting struct {
	tags    []string
	results map[string]*adapter.URLTestHistory
	carried []string
}

// forgetChanged is called before a configuration starts: the results of the dialers that
// are not in it as they were in the configuration started before are forgotten, and of
// those that dial through one of them. A dialer that is the same but for its tag (a server
// the provider renamed) takes the result of the tag it had. Nothing is forgotten at the first
// start of the process: the history is empty then.
func (h *sharedHistory) forgetChanged(next map[string]dialer) forgetting {
	h.access.Lock()
	defer h.access.Unlock()
	previous := h.started
	h.started = next
	if previous == nil {
		return forgetting{}
	}
	done := forgetting{results: make(map[string]*adapter.URLTestHistory), carried: h.carryRenamed(previous, next)}
	changed := make(map[string]bool)
	for tag, before := range previous {
		now, kept := next[tag]
		if !kept || !bytes.Equal(before.content, now.content) {
			changed[tag] = true
		}
	}
	for grew := len(changed) > 0; grew; {
		grew = false
		for tag, now := range next {
			if !changed[tag] && now.detour != "" && changed[now.detour] {
				changed[tag] = true
				grew = true
			}
		}
	}
	for tag := range changed {
		if result := h.storage.LoadURLTestHistory(tag); result != nil {
			done.results[tag] = result
		}
		h.storage.DeleteURLTestHistory(tag)
		done.tags = append(done.tags, tag)
	}
	return done
}

// undo takes back what forgetChanged did for a configuration that did not start: started are
// the dialers of the one that runs, which the next start compares with, and which keep their
// results (a result a group stored meanwhile stays); the tags given a result have none again.
func (h *sharedHistory) undo(done forgetting, started map[string]dialer) {
	h.access.Lock()
	defer h.access.Unlock()
	h.started = started
	for _, tag := range done.carried {
		h.storage.DeleteURLTestHistory(tag)
	}
	for tag, result := range done.results {
		if h.storage.LoadURLTestHistory(tag) == nil {
			h.storage.StoreURLTestHistory(tag, result)
		}
	}
}

// forget drops the results of the tags.
func (h *sharedHistory) forget(tags []string) {
	for _, tag := range tags {
		h.storage.DeleteURLTestHistory(tag)
	}
}

// Delays are the delays the URL tests of the process last found for the outbounds of the
// tags, in milliseconds; an outbound that was never tested, or failed its last test, is not
// there.
func Delays(tags []string) map[string]uint16 {
	result := make(map[string]uint16)
	for _, tag := range tags {
		if found := history.storage.LoadURLTestHistory(tag); found != nil && found.Delay > 0 {
			result[tag] = found.Delay
		}
	}
	return result
}

// carryRenamed gives a dialer of a tag that is new the result of the one gone of the same
// content but for the tag: a renamed server is not tested again. It returns the tags given one.
func (h *sharedHistory) carryRenamed(previous map[string]dialer, next map[string]dialer) []string {
	var carried []string
	for before, tag := range renamedTags(previous, next) {
		if result := h.storage.LoadURLTestHistory(before); result != nil {
			h.storage.StoreURLTestHistory(tag, result)
			carried = append(carried, tag)
		}
	}
	return carried
}

// renamedTags are the dialers of next that are one of previous under another tag: the tag gone
// with the one that has its content now.
func renamedTags(previous map[string]dialer, next map[string]dialer) map[string]string {
	gone := make(map[string]string)
	for tag, before := range previous {
		if _, kept := next[tag]; !kept {
			if body := withoutTag(before.content); body != "" {
				gone[body] = tag
			}
		}
	}
	renamed := make(map[string]string)
	if len(gone) == 0 {
		return renamed
	}
	for tag, now := range next {
		if _, existed := previous[tag]; existed {
			continue
		}
		body := withoutTag(now.content)
		if before, found := gone[body]; found {
			delete(gone, body)
			renamed[before] = tag
		}
	}
	return renamed
}

// withoutTag is the JSON of an outbound without its tag, its keys in order; empty when it
// cannot be read.
func withoutTag(content []byte) string {
	var fields map[string]json.RawMessage
	if json.Unmarshal(content, &fields) != nil {
		return ""
	}
	delete(fields, "tag")
	body, err := json.Marshal(fields)
	if err != nil {
		return ""
	}
	return string(body)
}
