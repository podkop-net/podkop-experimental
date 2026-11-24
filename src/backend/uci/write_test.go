package uci

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFormatReadsBack(t *testing.T) {
	t.Parallel()
	parsed, err := Parse([]byte(`
config settings 'settings'
	option quoted "it's \"x\""
	list source 'br-lan'
	list source 'br guest'
	option multi 'a
b'

config member
	option section 'main'

config member
	option section 'other'
`))
	require.NoError(t, err)
	text := parsed.Format()
	again, err := Parse(text)
	require.NoError(t, err)
	require.Equal(t, string(text), string(again.Format()))
	settings := again.Section("settings")
	require.Equal(t, `it's "x"`, settings.Get("quoted"))
	require.Equal(t, []string{"br-lan", "br guest"}, settings.List("source"))
	require.True(t, settings.IsList("source"))
	require.Equal(t, "a\nb", settings.Get("multi"))
	require.Equal(t, []string{"quoted", "source", "multi"}, settings.Options())
	members := again.SectionsOfType("member")
	require.Len(t, members, 2)
	require.True(t, members[0].Anonymous)
	require.Equal(t, "other", members[1].Get("section"))
	require.NotContains(t, string(text), "cfg", "an anonymous section is written without a name")
}

func TestSectionEdits(t *testing.T) {
	t.Parallel()
	section := NewSection("source", "src1", false)
	section.Set("type", "links")
	section.SetList("link", []string{"vless://a", "vless://b"})
	section.Set("label", "x")
	section.Set("type", "json")
	section.Delete("link")
	section.SetList("empty", nil)
	require.Equal(t, []string{"type", "label"}, section.Options())
	require.Equal(t, "json", section.Get("type"))
	parsed := &Package{Sections: []*Section{section}}
	require.Equal(t, "config source 'src1'\n\toption type 'json'\n\toption label 'x'\n", string(parsed.Format()))
}

// Options set to nothing are not read by libuci, so a file it writes has none of them; a list
// keeps its empty items.
func TestDropEmpty(t *testing.T) {
	t.Parallel()
	parsed, err := Parse([]byte("config settings 'settings'\n\toption a ''\n\toption b 'x'\n\toption c 'y'\n\toption c ''\n\tlist d ''\n\tlist e 'z'\n\tlist e ''\n\toption f ' '\n"))
	require.NoError(t, err)
	parsed.dropEmpty()
	settings := parsed.Section("settings")
	require.Equal(t, []string{"b", "c", "d", "e", "f"}, settings.Options())
	require.Equal(t, []string{""}, settings.List("d"))
	require.Equal(t, []string{"z", ""}, settings.List("e"))
	require.Equal(t, "config settings 'settings'\n\toption b 'x'\n\toption c 'y'\n\tlist d ''\n\tlist e 'z'\n\tlist e ''\n\toption f ' '\n", string(parsed.Format()))
}
