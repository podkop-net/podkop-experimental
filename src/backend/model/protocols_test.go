package model

import (
	"testing"

	"github.com/podkop-net/podkop-experimental/src/backend/uci"

	"github.com/stretchr/testify/require"
)

func TestProtocolName(t *testing.T) {
	t.Parallel()
	for text, want := range map[string]string{
		"vless": "vless", " VLESS ": "vless", "Hysteria2": "hysteria2", "hy2": "hysteria2", "ss": "shadowsocks", "Shadowsocks": "shadowsocks",
		"socks5": "socks", "SOCKS5H": "socks", "https": "http", "naive+https": "naive", "naive+quic": "naive",
		// neither a protocol nor a scheme: as it is, in small letters
		"VLES": "vles", "ssh": "ssh", "": "",
	} {
		require.Equal(t, want, ProtocolName(text), text)
	}
	for _, protocol := range Protocols {
		require.Equal(t, protocol, ProtocolName(protocol), "a name of Protocols is its own")
	}
}

func TestLinkProtocol(t *testing.T) {
	t.Parallel()
	for link, want := range map[string]string{
		"vless://u@a.example:443#NL":   "vless",
		" HY2://p@a.example:443#NL":    "hysteria2",
		"ss://x@a.example:8388":        "shadowsocks",
		"naive+quic://u:p@a.example":   "naive",
		"a.example:443":                "",
		"wireguard://k@a.example:1234": "wireguard",
	} {
		require.Equal(t, want, LinkProtocol(link), link)
	}
}

// The protocols of a row: a list, or an option of names by commas or spaces as a user types them,
// each once, in the order of the settings; a name that is none stays. Nothing written, or only
// separators, takes every protocol.
func TestProtocolsOfRows(t *testing.T) {
	t.Parallel()
	load := func(options string) Member {
		parsed, err := uci.Parse([]byte("config settings 'settings'\n\toption config_version '2'\n" +
			"\nconfig section 'main'\n\nconfig member\n\toption section 'main'\n\toption source 'prov1'\n" + options))
		require.NoError(t, err)
		config, err := Load(parsed)
		require.NoError(t, err)
		return config.Section("main").Servers[0]
	}
	for options, want := range map[string][]string{
		"":                           nil,
		"\toption protocols ''\n":    nil,
		"\toption protocols ' , '\n": nil,
		"\tlist protocols 'VLESS'\n\tlist protocols 'hy2'\n":                         {"vless", "hysteria2"},
		"\toption protocols 'hysteria2, Vless,ss  trojan'\n":                         {"hysteria2", "vless", "shadowsocks", "trojan"},
		"\tlist protocols 'socks5'\n\tlist protocols 'SOCKS'\n":                      {"socks"},
		"\tlist protocols 'vles'\n\tlist protocols ' '\n\tlist protocols 'trojan'\n": {"vles", "trojan"},
	} {
		require.Equal(t, want, load(options).Protocols, options)
	}

	row := load("\tlist protocols 'VLESS'\n\tlist protocols 'hy2'\n")
	require.True(t, row.TakesProtocol("vless"))
	require.True(t, row.TakesProtocol("hysteria2"))
	require.True(t, row.TakesProtocol(LinkProtocol("hy2://p@a.example:443")))
	require.False(t, row.TakesProtocol("hysteria"))
	require.False(t, row.TakesProtocol("shadowsocks"))
	require.False(t, row.TakesProtocol(""), "a server of no type is of no protocol")
	require.True(t, (&Member{}).TakesProtocol("anything"))
	require.True(t, (&Member{}).TakesProtocol(""))
	require.True(t, row.Takes("any name"), "the names and the protocols are apart")
}
