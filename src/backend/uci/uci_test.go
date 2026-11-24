package uci

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	t.Parallel()
	parsed, err := Parse([]byte(`
# a comment
config settings 'settings'
	option dns_type 'udp'   # after a value
	option quoted "a \"b\" c"
	option glued 'one'"two"three
	list source 'br-lan'
	list source 'br-guest'
	option flag 'yes'

config section 'main'
	option outbound_json '{
  "type": "direct",
  "tag": "x"
}'
	option empty ''
config section second; option connection_type block
`))
	require.NoError(t, err)
	require.Len(t, parsed.Sections, 3)
	settings := parsed.Section("settings")
	require.Equal(t, "settings", settings.Type)
	require.Equal(t, "udp", settings.Get("dns_type"))
	require.Equal(t, `a "b" c`, settings.Get("quoted"))
	require.Equal(t, "onetwothree", settings.Get("glued"))
	require.Equal(t, "br-lan br-guest", settings.Get("source"))
	require.Equal(t, []string{"br-lan", "br-guest"}, settings.List("source"))
	require.True(t, settings.Bool("flag", false))
	require.True(t, settings.Bool("missing", true))
	require.False(t, settings.Has("missing"))
	main := parsed.Section("main")
	require.Equal(t, "{\n  \"type\": \"direct\",\n  \"tag\": \"x\"\n}", main.Get("outbound_json"))
	require.True(t, main.Has("empty"))
	require.Equal(t, "", main.Get("empty"))
	require.Equal(t, "block", parsed.Section("second").Get("connection_type"))
	require.Equal(t, []string{"main", "second"}, names(parsed.SectionsOfType("section")))
}

func TestParseOptionAfterList(t *testing.T) {
	t.Parallel()
	parsed, err := Parse([]byte("config s 'a'\n\tlist x '1'\n\tlist x '2'\n\toption x '3'\n\tlist y '1'\n\toption z 'v'\n\tlist z 'w'\n"))
	require.NoError(t, err)
	section := parsed.Section("a")
	require.Equal(t, []string{"3"}, section.List("x"))
	require.Equal(t, []string{"v", "w"}, section.List("z"))
}

func TestParseSameSectionTwice(t *testing.T) {
	t.Parallel()
	parsed, err := Parse([]byte("config s 'a'\n\toption x '1'\nconfig s 'b'\nconfig s 'a'\n\toption y '2'\n"))
	require.NoError(t, err)
	require.Equal(t, []string{"a", "b"}, names(parsed.Sections))
	require.Equal(t, "1", parsed.Section("a").Get("x"))
	require.Equal(t, "2", parsed.Section("a").Get("y"))
}

func TestParseErrors(t *testing.T) {
	t.Parallel()
	for _, text := range []string{
		"option x 'y'\n",
		"config s 'a'\n\toption x\n",
		"config s 'a'\n\toption x 'open\n",
		"config s 'a'\n\toption x \"open\n",
		"config s 'a'\n\tsomething x 'y'\n",
	} {
		_, err := Parse([]byte(text))
		require.Error(t, err, text)
	}
}

func names(sections []*Section) []string {
	var result []string
	for _, section := range sections {
		result = append(result, section.Name)
	}
	return result
}

// libuci names a section written without a name by its number in the file and its type.
// The names here are the ones a router shows: the first is what the shell backend of
// podkop made of such a section on OpenWrt 24.10, the others are the firewall's.
func TestParseAnonymousSections(t *testing.T) {
	t.Parallel()
	parsed, err := Parse([]byte("config settings 'settings'\n\nconfig section\n\toption a 'b'\n\nconfig settings 'settings'\n\toption c 'd'\n\nconfig section ''\n"))
	require.NoError(t, err)
	require.Len(t, parsed.Sections, 3)
	require.Equal(t, "cfg02d2da", parsed.Sections[1].Name)
	require.Equal(t, "b", parsed.Sections[1].Get("a"))
	// the second block of "settings" made no section: the next one is the third
	require.Equal(t, "cfg03d2da", parsed.Sections[2].Name)
	require.Equal(t, "cfg01e63d", anonymousName(1, "defaults"))
	require.Equal(t, "cfg03dc81", anonymousName(3, "zone"))
	require.Equal(t, "cfg0592bd", anonymousName(5, "rule"))
}

func TestIsOne(t *testing.T) {
	t.Parallel()
	for _, text := range []string{"1", " 1", "1 ", "01", "+1", "001"} {
		require.True(t, IsOne(text), text)
	}
	for _, text := range []string{"", "0", "2", "11", "on", "true", "1x", "-1", "10", "+", "++1", "0+1", "\r1"} {
		require.False(t, IsOne(text), text)
	}
}
