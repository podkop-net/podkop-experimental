package model

import (
	"testing"

	"github.com/podkop-net/podkop-experimental/src/backend/uci"

	"github.com/stretchr/testify/require"
)

// One name per site, the shortest of it, in the order the sites come; sites of the skipped names,
// comments, blanks and lines that are no host name are left out.
func TestMaskNames(t *testing.T) {
	t.Parallel()
	list := "# whitelist\n" +
		"00.img.avito.st\n" +
		"img.avito.st\n" +
		"01.img.avito.st\n" +
		"\n" +
		"  Mail.RU  \n" +
		"top-fwz1.mail.ru # counter\n" +
		"*.vk.com\n" +
		"gosuslugi.ru.\n" +
		"10.0.0.1\n" +
		"localhost\n" +
		"bad_name.example\n" +
		"www.deepl.com\n" +
		"news.bbc.co.uk\n" +
		"bbc.co.uk\n"
	names := MaskNames([]byte(list), []string{"deepl.com"})
	require.Equal(t, []string{"img.avito.st", "mail.ru", "vk.com", "gosuslugi.ru", "bbc.co.uk"}, names)
	require.Empty(t, MaskNames([]byte("<html><body>blocked</body></html>\n"), nil))
}

// The lists are the default ones unless the settings name others or turn them off.
func TestMaskLists(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		options string
		want    []string
	}{
		{"", DefaultMaskLists},
		{"\tlist mask_list_url 'https://lists.example/white.txt'\n\tlist mask_list_url ' https://lists.example/more.txt'\n" +
			"\tlist mask_list_url 'https://lists.example/white.txt'\n", []string{"https://lists.example/white.txt", "https://lists.example/more.txt"}},
		{"\toption mask_list_url 'https://lists.example/white.txt'\n", []string{"https://lists.example/white.txt"}},
		{"\toption mask_list '0'\n\tlist mask_list_url 'https://lists.example/white.txt'\n", nil},
		{"\toption mask_list '1'\n\tlist mask_list_url ' '\n", DefaultMaskLists},
	} {
		parsed, err := uci.Parse([]byte("config settings 'settings'\n\toption config_version '2'\n" + test.options))
		require.NoError(t, err)
		config, err := Load(parsed)
		require.NoError(t, err)
		require.Equal(t, test.want, config.Settings.MaskLists, test.options)
	}
}
