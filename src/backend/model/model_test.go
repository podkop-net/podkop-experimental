package model

import (
	"testing"

	"github.com/podkop-net/podkop-experimental/src/backend/uci"

	"github.com/stretchr/testify/require"
)

func TestLoadDefaults(t *testing.T) {
	t.Parallel()
	// a file of podkop 0.7, read as podkop migrate converts it
	parsed, err := uci.Parse([]byte("config settings 'settings'\n\toption dns_server ''\n\nconfig section 'main'\n\toption connection_type 'proxy'\n\toption proxy_config_type 'selector'\n\tlist selector_proxy_links 'a://1'\n\tlist selector_proxy_links 'b://2 c://3'\n"))
	require.NoError(t, err)
	config, err := Load(parsed)
	require.NoError(t, err)
	require.Equal(t, "doh", config.Settings.DNSType)
	require.Equal(t, "1.1.1.1", config.Settings.DNSServer)
	require.Equal(t, "77.88.8.8", config.Settings.BootstrapDNSServer)
	require.Equal(t, "60", config.Settings.DNSRewriteTTL)
	require.Equal(t, "1d", config.Settings.UpdateInterval)
	require.Equal(t, "warn", config.Settings.LogLevel)
	require.Equal(t, "/var/run/podkop/cache.db", config.Settings.CachePath)
	require.Equal(t, Check{Interval: "3m", Tolerance: "50", TestingURL: "https://www.gstatic.com/generate_204", DownloadCheck: "default"}, config.Settings.Check)
	require.Len(t, config.Sections, 1)
	section := &config.Sections[0]
	require.True(t, section.Enabled)
	require.Equal(t, []Member{{Source: "main_links"}}, section.Servers)
	source := config.Source("main_links")
	require.NotNil(t, source)
	require.Equal(t, "links", source.Type)
	require.Equal(t, []string{"a://1", "b://2", "c://3"}, source.Links)
	require.Equal(t, "auto", source.UpdateInterval)
	require.Equal(t, "disabled", section.UserDomainListType)
	require.False(t, section.HasEnabledLists())
	require.Equal(t, ExitServers, config.Exit(section))
	require.True(t, config.HasOutbound(section))
}

func TestLoadNoSettings(t *testing.T) {
	t.Parallel()
	parsed, err := uci.Parse([]byte("config section 'main'\n"))
	require.NoError(t, err)
	_, err = Load(parsed)
	require.Error(t, err)
	// a section of another type named settings is no settings
	parsed, err = uci.Parse([]byte("config section 'settings'\n\toption connection_type 'proxy'\n"))
	require.NoError(t, err)
	_, err = Load(parsed)
	require.Error(t, err)
}

func TestValues(t *testing.T) {
	t.Parallel()
	for _, text := range []string{"1.2.3.4", "0.0.0.0", "255.255.255.255", "10.0.0.1"} {
		require.True(t, IsIPv4(text), text)
	}
	for _, text := range []string{"", "1.2.3", "1.2.3.4.5", "256.1.1.1", "01.2.3.4", "1.2.3.4.", "a.b.c.d", "1.2.3.4/24", "1234"} {
		require.False(t, IsIPv4(text), text)
	}
	for _, text := range []string{"1.2.3.0/24", "0.0.0.0/0", "1.2.3.4/32", "1.2.3.4/9", "1.2.3.4/19", "1.2.3.4/29"} {
		require.True(t, IsIPv4CIDR(text), text)
	}
	for _, text := range []string{"1.2.3.4", "1.2.3.4/33", "1.2.3.4/", "1.2.3.4/08", "1.2.3.4/123", "1.2.3/24"} {
		require.False(t, IsIPv4CIDR(text), text)
	}
	for _, text := range []string{"example.com", ".example.com", "a", "xn--p1ai", "a-b.c1", "1.2.3.4"} {
		require.True(t, IsDomainSuffix(text), text)
	}
	for _, text := range []string{"", ".", "Example.com", "a..b", "-a.com", "a-.com", "a.com/x", "a b", "..a"} {
		require.False(t, IsDomainSuffix(text), text)
	}
}

func TestIsOne(t *testing.T) {
	t.Parallel()
	for _, text := range []string{"1", " 1", "1 ", "01", "+1", "001"} {
		require.True(t, isOne(text), text)
	}
	for _, text := range []string{"", "0", "2", "11", "on", "true", "1x", "-1", "10", "+"} {
		require.False(t, isOne(text), text)
	}
}

// The cache file is never in a directory of the sing-box package: the places podkop 0.7
// offered are taken to the backend's own.
func TestCachePathMoved(t *testing.T) {
	t.Parallel()
	for path, want := range map[string]string{
		"/tmp/sing-box/cache.db":       "/var/run/podkop/cache.db",
		"/usr/share/sing-box/cache.db": "/usr/share/podkop/cache.db",
		"/mnt/usb/cache.db":            "/mnt/usb/cache.db",
	} {
		parsed, err := uci.Parse([]byte("config settings 'settings'\n\toption cache_path '" + path + "'\n\nconfig section 'main'\n\toption connection_type 'proxy'\n\toption proxy_string 'socks5://203.0.113.15:1080'\n"))
		require.NoError(t, err)
		config, err := Load(parsed)
		require.NoError(t, err)
		require.Equal(t, want, config.Settings.CachePath, path)
	}
}

func TestSourcesAndMembers(t *testing.T) {
	t.Parallel()
	parsed, err := uci.Parse([]byte("config settings 'settings'\n\toption config_version '2'\n\toption urltest_check_interval '1m'\n" +
		"\nconfig source 'prov1'\n\toption type 'subscription'\n\toption url ' https://a.example/sub/1 '\n" +
		"\nconfig source 'warp'\n\toption type 'interface'\n\toption interface 'awg0'\n\toption domain_resolver_enabled '1'\n\toption domain_resolver_dns_server '1.1.1.1'\n" +
		"\nconfig source 'empty'\n" +
		"\nconfig section 'youtube'\n\toption label 'YouTube'\n" +
		"\nconfig section 'off'\n\toption enabled '0'\n" +
		"\nconfig section 'ads'\n" +
		"\nconfig section 'waiting'\n" +
		"\nconfig member\n\toption section 'youtube'\n\toption role 'server'\n\toption source 'prov1'\n\tlist include 'NL'\n\tlist include ' '\n\tlist exclude 'old'\n\toption via 'warp'\n" +
		"\nconfig member\n\toption section 'youtube'\n\toption role 'fallback'\n\toption source 'direct'\n" +
		"\nconfig member\n\toption section 'ads'\n\toption role 'server'\n\toption source 'block'\n" +
		"\nconfig member\n\toption section 'waiting'\n\toption role 'server'\n\toption source 'empty'\n" +
		"\nconfig member\n\toption section 'gone'\n\toption source 'prov1'\n"))
	require.NoError(t, err)
	config, err := Load(parsed)
	require.NoError(t, err)
	require.Equal(t, "1m", config.Settings.Check.Interval)
	require.Equal(t, Source{Name: "prov1", Type: "subscription", URL: "https://a.example/sub/1", UpdateInterval: "auto", DomainResolverDNSType: "udp"}, *config.Source("prov1"))
	require.True(t, config.Source("warp").DomainResolverEnabled)
	require.False(t, config.Source("empty").Filled())
	youtube := config.Section("youtube")
	require.Equal(t, "YouTube", youtube.Label)
	require.Equal(t, []Member{{Source: "prov1", Include: []string{"NL"}, Exclude: []string{"old"}, Via: "warp"}}, youtube.Servers)
	require.Equal(t, []Member{{Source: "direct"}}, youtube.Fallbacks)
	require.Equal(t, ExitServers, config.Exit(youtube))
	require.False(t, config.HasOutbound(config.Section("off")))
	require.Equal(t, ExitBlock, config.Exit(config.Section("ads")))
	require.Equal(t, ExitNone, config.Exit(config.Section("waiting")))
	row := youtube.Servers[0]
	require.True(t, row.Takes("🇳🇱 NL-1"))
	require.False(t, row.Takes("🇳🇱 NL old"))
	require.False(t, row.Takes("DE"))
	require.True(t, (&Member{}).Takes("anything"))
}

func TestNameHas(t *testing.T) {
	t.Parallel()
	require.True(t, NameHas("🇺🇸 USA AI-1", "AI"))
	require.False(t, NameHas("🇪🇸 Spain", "AI"))
	require.True(t, NameHas("🇳🇱 Netherlands 2", "nether"))
	require.True(t, NameHas("Нидерланды 1 ⚡", "нидер"))
	require.True(t, NameHas("🇺🇸 USA AI-1", "AI-1"), "a word with a dash is looked for as it is")
	require.True(t, NameHas("🇩🇪 Germany", "🇩🇪"))
	require.False(t, NameHas("anything", " "))
}

func TestReservedSourceNames(t *testing.T) {
	t.Parallel()
	parsed, err := uci.Parse([]byte("config settings 'settings'\n\toption config_version '2'\n\nconfig source 'block'\n"))
	require.NoError(t, err)
	_, err = Load(parsed)
	require.ErrorContains(t, err, "cannot be named block")
}
