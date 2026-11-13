package migrate

import (
	"fmt"

	"github.com/podkop-net/podkop-experimental/src/backend/uci"
)

// Tidy brings settings of the format Version up to what this backend reads where the format
// did not change: options of the settings that became options of the rules. It tells what it
// did, for the journal, and whether it changed the settings.
func Tidy(parsed *uci.Package) ([]string, bool) {
	var notes []string
	note, changed := downloadLists(parsed)
	if note != "" {
		notes = append(notes, note)
	}
	return notes, changed
}

// downloadLists moves the old choice of the server the lists downloaded through:
// download_lists_via_proxy of the settings and the section download_lists_via_proxy_section
// named (podkop 0.7, podkop-exp up to 0.8.13; 0.8.14 read them no more) become the option
// download_lists of that section: the lists and the subscriptions download through its servers,
// directly first. The options of the settings go either way.
func downloadLists(parsed *uci.Package) (string, bool) {
	settings := parsed.Section("settings")
	if settings == nil || settings.Type != "settings" {
		return "", false
	}
	via, name := settings.Get("download_lists_via_proxy"), settings.Get("download_lists_via_proxy_section")
	if !settings.Has("download_lists_via_proxy") && !settings.Has("download_lists_via_proxy_section") {
		return "", false
	}
	settings.Delete("download_lists_via_proxy")
	settings.Delete("download_lists_via_proxy_section")
	if !isOne(via) {
		return "", true
	}
	section := parsed.Section(name)
	if section == nil || section.Type != "section" {
		return fmt.Sprintf("the lists downloaded through the section %q, which is not there: they download directly, then through the servers of every rule", name), true
	}
	section.Set("download_lists", "1")
	return fmt.Sprintf("the lists downloaded through the section %s: its rule downloads the lists and the subscriptions through its servers now, directly first", name), true
}
