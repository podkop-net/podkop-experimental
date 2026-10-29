package migrate

import (
	"os"
	"strings"
	"testing"

	"github.com/podkop-net/podkop-experimental/src/backend/uci"
	"github.com/stretchr/testify/require"
)

func parse(t *testing.T, text string) *uci.Package {
	t.Helper()
	parsed, err := uci.Parse([]byte(text))
	require.NoError(t, err)
	return parsed
}

// row is a member as the tests compare it.
type row struct {
	role, source, via string
	include, exclude  string
}

func rows(parsed *uci.Package, section string) []row {
	var result []row
	for _, member := range parsed.SectionsOfType("member") {
		if member.Get("section") != section {
			continue
		}
		result = append(result, row{
			role: member.Get("role"), source: member.Get("source"), via: member.Get("via"),
			include: strings.Join(member.List("include"), ","), exclude: strings.Join(member.List("exclude"), ","),
		})
	}
	return result
}

// convert converts, writes the file and reads it back, as the router does.
func convert(t *testing.T, text string) (*uci.Package, []string) {
	t.Helper()
	parsed := parse(t, text)
	notes := Convert(parsed)
	return parse(t, string(parsed.Format())), notes
}

// The settings podkop 0.7 and podkop-exp up to 0.8.7 install: one section with an empty link.
func TestConvertDefault(t *testing.T) {
	t.Parallel()
	parsed, notes := convert(t, `
config settings 'settings'
	option dns_type 'udp'
	list source_network_interfaces 'br-lan'

config section 'main'
	option connection_type 'proxy'
	option proxy_config_type 'url'
	option proxy_string ''
	option enable_udp_over_tcp '0'
	list community_lists 'russia_inside'
`)
	require.Empty(t, notes)
	require.Equal(t, Version, parsed.Section("settings").Get("config_version"))
	source := parsed.Section("main_link")
	require.NotNil(t, source)
	require.Equal(t, "source", source.Type)
	require.Equal(t, "links", source.Get("type"))
	require.False(t, source.Has("link"), "an empty link is a source waiting for one")
	require.Equal(t, []row{{role: "server", source: "main_link"}}, rows(parsed, "main"))
	main := parsed.Section("main")
	require.Equal(t, "russia_inside", main.Get("community_lists"))
	for _, name := range exitOptions {
		require.False(t, main.Has(name), name)
	}
	require.False(t, Needed(parsed))
}

func TestConvertEverything(t *testing.T) {
	t.Parallel()
	parsed, notes := convert(t, `
config settings 'settings'
	option dns_type 'udp'

config subscription 'prov1'
	option url 'https://sub.example/x'

config subscription 'prov2'
	option url 'https://sub2.example/y'
	option update_interval '1h'

config group 'nl'
	list subscription 'prov1'
	list include 'NL'
	option empty 'all'

config group 'gm'
	list subscription 'prov1'
	list subscription 'prov2'
	list exclude 'RU'
	option empty 'section'
	option empty_section 'warp'

config group 'any'
	list subscription 'prov2'
	option empty 'block'

config section 'main'
	option connection_type 'proxy'
	option proxy_config_type 'urltest'
	list urltest_proxy_links 'vless://a@192.0.2.1:443#A'
	list urltest_proxy_links 'vless://b@192.0.2.2:443#B'
	list urltest_fallback_links 'hy2://c@192.0.2.3:443#C'
	list urltest_fallback_links 'trojan://d@192.0.2.4:443#D'
	option urltest_check_interval '1m'
	option urltest_tolerance '100'
	option detour 'warp'
	option enable_udp_over_tcp '1'
	list community_lists 'russia_inside'

config section 'warp'
	option connection_type 'vpn'
	option interface 'awg0'
	option domain_resolver_enabled '1'
	option domain_resolver_dns_type 'doh'
	option domain_resolver_dns_server '1.1.1.1'
	list community_lists 'meta'

config section 'yt'
	option connection_type 'group'
	list group 'nl'
	list community_lists 'youtube'

config section 'gem'
	option connection_type 'group'
	option group 'gm'

config section 'tg'
	option connection_type 'group'
	option group 'any'
	option detour 'warp'

config section 'sel'
	option connection_type 'proxy'
	option proxy_config_type 'selector'
	list selector_proxy_links 'ss://x@192.0.2.5:8388#S1 ss://y@192.0.2.6:8388#S2'

config section 'js'
	option connection_type 'proxy'
	option proxy_config_type 'outbound'
	option outbound_json '{
  "type": "trojan",
  "tag": "it'\''s"
}'

config section 'ads'
	option connection_type 'block'

config section 'bank'
	option connection_type 'exclusion'

config section 'sel_links'
	list user_domains 'example.com'
`)
	require.Len(t, notes, 3)
	require.Contains(t, strings.Join(notes, "\n"), "selector")
	require.Contains(t, strings.Join(notes, "\n"), "block and exclusion went first")
	var order []string
	for _, section := range parsed.SectionsOfType("section") {
		order = append(order, section.Name)
	}
	require.Equal(t, []string{"ads", "bank", "main", "warp", "yt", "gem", "tg", "sel", "js", "sel_links"}, order)
	require.Contains(t, strings.Join(notes, "\n"), "the section tg connected through the section warp, which only a proxy section could")

	settings := parsed.Section("settings")
	require.Equal(t, "1m", settings.Get("urltest_check_interval"))
	require.Equal(t, "100", settings.Get("urltest_tolerance"))

	require.Equal(t, "source", parsed.Section("prov1").Type)
	require.Equal(t, "subscription", parsed.Section("prov1").Get("type"))
	require.Equal(t, "12h", parsed.Section("prov1").Get("update_interval"))
	require.Equal(t, "1h", parsed.Section("prov2").Get("update_interval"))
	require.Equal(t, "prov1", parsed.Section("prov1").Get("label"))
	require.Empty(t, parsed.SectionsOfType("group"))
	require.Empty(t, parsed.SectionsOfType("subscription"))

	links := parsed.Section("main_links")
	require.Equal(t, []string{"vless://a@192.0.2.1:443#A", "vless://b@192.0.2.2:443#B"}, links.List("link"))
	require.Equal(t, "1", links.Get("udp_over_tcp"))
	require.Equal(t, []string{"hy2://c@192.0.2.3:443#C"}, parsed.Section("main_fallback1").List("link"))
	require.Equal(t, []string{"trojan://d@192.0.2.4:443#D"}, parsed.Section("main_fallback2").List("link"))
	require.Equal(t, []row{
		{role: "server", source: "main_links", via: "warp_if"},
		{role: "fallback", source: "main_fallback1", via: "warp_if"},
		{role: "fallback", source: "main_fallback2", via: "warp_if"},
	}, rows(parsed, "main"))

	warp := parsed.Section("warp_if")
	require.Equal(t, "interface", warp.Get("type"))
	require.Equal(t, "awg0", warp.Get("interface"))
	require.Equal(t, "1", warp.Get("domain_resolver_enabled"))
	require.Equal(t, "doh", warp.Get("domain_resolver_dns_type"))
	require.Equal(t, "1.1.1.1", warp.Get("domain_resolver_dns_server"))
	require.Equal(t, []row{{role: "server", source: "warp_if"}}, rows(parsed, "warp"))

	require.Equal(t, []row{
		{role: "server", source: "prov1", include: "NL"},
		{role: "fallback", source: "prov1"},
	}, rows(parsed, "yt"))
	require.Equal(t, []row{
		{role: "server", source: "prov1", exclude: "RU"},
		{role: "server", source: "prov2", exclude: "RU"},
		{role: "fallback", source: "warp_if"},
	}, rows(parsed, "gem"))
	require.Equal(t, []row{
		{role: "server", source: "prov2"},
		{role: "fallback", source: "block"},
	}, rows(parsed, "tg"))

	// the name of a section takes the name the selector's source would have had
	require.Equal(t, "section", parsed.Section("sel_links").Type)
	require.Equal(t, []string{"ss://x@192.0.2.5:8388#S1", "ss://y@192.0.2.6:8388#S2"}, parsed.Section("sel_links_2").List("link"))
	require.Equal(t, []row{{role: "server", source: "sel_links_2"}}, rows(parsed, "sel"))
	require.Empty(t, rows(parsed, "sel_links"))

	require.Equal(t, "{\n  \"type\": \"trojan\",\n  \"tag\": \"it's\"\n}", parsed.Section("js_json").Get("outbound_json"))
	require.Equal(t, []row{{role: "server", source: "block"}}, rows(parsed, "ads"))
	require.Equal(t, []row{{role: "server", source: "direct"}}, rows(parsed, "bank"))

	for _, section := range parsed.SectionsOfType("section") {
		for _, name := range append(exitOptions, checkOptions...) {
			require.False(t, section.Has(name), section.Name+"."+name)
		}
	}

	// settings first, then the sources, the sections and their rows
	var types []string
	for _, section := range parsed.Sections {
		if len(types) == 0 || types[len(types)-1] != section.Type {
			types = append(types, section.Type)
		}
	}
	require.Equal(t, []string{"settings", "source", "section", "member"}, types)
}

func TestConvertTwiceChangesNothing(t *testing.T) {
	t.Parallel()
	parsed := parse(t, `
config settings 'settings'

config section 'main'
	option connection_type 'vpn'
	option interface 'wg0'
`)
	Convert(parsed)
	once := string(parsed.Format())
	require.Empty(t, Convert(parsed))
	require.Equal(t, once, string(parsed.Format()))
	again := parse(t, once)
	require.Empty(t, Convert(again))
	require.Equal(t, once, string(again.Format()))
}

func TestConvertNotes(t *testing.T) {
	t.Parallel()
	parsed, notes := convert(t, `
config settings 'settings'

config section 'lost'
	option connection_type 'group'
	option group 'gone'

config section 'odd'
	option connection_type 'teleport'

config section 'a'
	option connection_type 'proxy'
	option proxy_string 'vless://a@192.0.2.1:443#A'
	option detour 'ads'

config section 'ads'
	option connection_type 'block'

config section 'u1'
	option connection_type 'proxy'
	option proxy_config_type 'urltest'
	option urltest_check_interval '1m'

config section 'u2'
	option connection_type 'proxy'
	option proxy_config_type 'urltest'
	option urltest_check_interval '5m'
`)
	require.Len(t, notes, 5)
	joined := strings.Join(notes, "\n")
	require.Contains(t, joined, "went first, as their rules did: ads, lost, odd, a, u1, u2")
	require.Contains(t, joined, "u1 and u2 checked their servers differently")
	require.Contains(t, joined, "the group gone, which is not there")
	require.Contains(t, joined, "\"teleport\"")
	require.Contains(t, joined, "the section a connected through the section ads, which has no server now")
	require.Empty(t, rows(parsed, "lost"))
	require.Equal(t, []row{{role: "server", source: "a_link"}}, rows(parsed, "a"))
	require.Equal(t, "1m", parsed.Section("settings").Get("urltest_check_interval"))
}

func TestConvertEmptyGroupToSectionWithoutServers(t *testing.T) {
	t.Parallel()
	parsed, notes := convert(t, `
config settings 'settings'

config subscription 'prov1'
	option url 'https://sub.example/x'

config group 'g'
	list subscription 'prov1'
	list include 'NL'
	option empty 'section'
	option empty_section 'plain'

config section 'yt'
	option connection_type 'group'
	option group 'g'

config section 'plain'
	list user_domains 'example.com'
`)
	require.Len(t, notes, 1)
	require.Equal(t, []row{
		{role: "server", source: "prov1", include: "NL"},
		{role: "fallback", source: "block"},
	}, rows(parsed, "yt"))
}

func TestNeeded(t *testing.T) {
	t.Parallel()
	require.True(t, Needed(parse(t, "config settings 'settings'\n")))
	require.False(t, Needed(parse(t, "config settings 'settings'\n\toption config_version '2'\n")))
	require.False(t, Needed(parse(t, "config section 'main'\n")), "no settings: nothing to convert")
}

func TestFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := dir + "/podkop"
	old := "config settings 'settings'\n\nconfig section 'main'\n\toption connection_type 'exclusion'\n"
	require.NoError(t, os.WriteFile(path, []byte(old), 0o600))
	notes, err := File(path)
	require.NoError(t, err)
	require.Contains(t, notes[0], Backup(path))
	kept, err := os.ReadFile(Backup(path))
	require.NoError(t, err)
	require.Equal(t, old, string(kept))
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	converted, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Contains(t, string(converted), "option config_version '2'")
	notes, err = File(path)
	require.NoError(t, err)
	require.Empty(t, notes, "a converted file is left alone")
	// a backup of 0.8 restored later: the first copy stays
	require.NoError(t, os.WriteFile(path, []byte(old+"\toption user_domains 'x'\n"), 0o600))
	_, err = File(path)
	require.NoError(t, err)
	kept, err = os.ReadFile(Backup(path))
	require.NoError(t, err)
	require.Equal(t, old, string(kept))
}
