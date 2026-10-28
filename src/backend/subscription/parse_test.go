package subscription

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// fakeDecode decodes a link the way the engine does as far as Parse sees it: an outbound
// whose tag is the name of the link; "bad://" links are refused.
func fakeDecode(link string) ([]byte, []string, error) {
	parsed, err := url.Parse(link)
	if err != nil || parsed.Scheme == "bad" {
		return nil, nil, errors.New("unsupported link type")
	}
	var warnings []string
	if parsed.Query().Get("extra") != "" {
		warnings = append(warnings, "extra is not supported and is ignored")
	}
	content, _ := json.Marshal(map[string]any{"type": parsed.Scheme, "tag": parsed.Fragment, "server": parsed.Hostname(), "uuid": parsed.User.Username()})
	return content, warnings, nil
}

func TestParseBase64List(t *testing.T) {
	t.Parallel()
	links := []string{
		"vless://u1@nl1.example:443?security=reality#%F0%9F%87%B3%F0%9F%87%B1%20Netherlands",
		"vless://u2@de1.example:443?security=reality#Germany%20%E2%9A%A1",
		"trojan://p@fi.example:443#Finland?serverDescription=QmVzdA",
		"bad://what#Broken",
	}
	body := base64.StdEncoding.EncodeToString([]byte(strings.Join(links, "\n") + "\n"))
	// as Marzban breaks it into lines
	body = body[:20] + "\n" + body[20:]
	servers, err := Parse([]byte(body), fakeDecode)
	require.NoError(t, err)
	require.Len(t, servers, 4)
	require.Equal(t, "🇳🇱 Netherlands", servers[0].Name)
	require.Equal(t, "Germany ⚡", servers[1].Name)
	require.Equal(t, "Finland", servers[2].Name)
	require.Equal(t, "Broken", servers[3].Name)
	require.True(t, servers[0].Usable())
	require.NotEmpty(t, servers[0].ID)
	require.NotEqual(t, servers[0].ID, servers[1].ID)
	require.False(t, servers[3].Usable())
	require.Empty(t, servers[3].ID)
	require.Equal(t, links[0], servers[0].Link)
}

func TestParsePlainListWithComments(t *testing.T) {
	t.Parallel()
	body := "\ufeff#profile-title: base64:VGVzdA==\n#announce: hello\nhapp://routing/onadd/xyz\n\nvless://u1@a.example:443?extra=1#A\r\nss://x@b.example:8388\nnot a link\n"
	servers, err := Parse([]byte(body), fakeDecode)
	require.NoError(t, err)
	require.Len(t, servers, 2)
	require.Equal(t, "A", servers[0].Name)
	require.Equal(t, []string{"extra is not supported and is ignored"}, servers[0].Notes)
	// no name: the number of the server
	require.Equal(t, "server 2", servers[1].Name)
}

func TestParseIDIgnoresName(t *testing.T) {
	t.Parallel()
	first, err := Parse([]byte("vless://u1@a.example:443#Days%20left%2030\n"), fakeDecode)
	require.NoError(t, err)
	second, err := Parse([]byte("vless://u1@a.example:443#Days%20left%2029\n"), fakeDecode)
	require.NoError(t, err)
	require.Equal(t, first[0].ID, second[0].ID)
	require.NotEqual(t, first[0].Name, second[0].Name)
	require.True(t, SameServers(first, second))
	third, err := Parse([]byte("vless://u2@a.example:443#Days%20left%2029\n"), fakeDecode)
	require.NoError(t, err)
	require.False(t, SameServers(first, third))
}

func TestParseRefusesWhatIsNoList(t *testing.T) {
	t.Parallel()
	for body, code := range map[string]string{
		"":                                    "empty",
		"   \n":                               "empty",
		"<!doctype html><html>blocked</html>": "page",
		`{"outbounds":[]}`:                    "json",
		`[{"remarks":"a"}]`:                   "json",
		"proxies:\n  - name: a\n":             "clash",
		"just some words\n":                   "nolinks",
		base64.StdEncoding.EncodeToString([]byte("<html></html>")): "page",
	} {
		_, err := Parse([]byte(body), fakeDecode)
		require.Equal(t, code, err.(*Failure).Code, body)
	}
}

// What Remnawave sends instead of the servers of an ended subscription: links to 0.0.0.0,
// its notes in the names. The list there was stays.
func TestParsePlaceholderNotes(t *testing.T) {
	t.Parallel()
	_, err := Parse([]byte("vless://00000000-0000-0000-0000-000000000000@0.0.0.0:1?security=none#%E2%8C%9B%20Subscription%20expired\n"+
		"vless://00000000-0000-0000-0000-000000000000@0.0.0.0:1?security=none#Contact%20support\n"), fakeDecode)
	require.Equal(t, "placeholder", err.(*Failure).Code)
	require.Equal(t, []string{"⌛ Subscription expired; Contact support"}, err.(*Failure).Args)
	servers, err := Parse([]byte("vless://u@0.0.0.0:1#Note\nvless://u2@a.example:443#A\n"), fakeDecode)
	require.NoError(t, err, "one real server: a list")
	require.Len(t, servers, 2)
}

func TestSameServersIgnoresOrder(t *testing.T) {
	t.Parallel()
	servers, err := Parse([]byte("vless://u1@a.example:443#A\nvless://u2@b.example:443#B\nbad://c#C\n"), fakeDecode)
	require.NoError(t, err)
	reversed := []Server{servers[2], servers[1], servers[0]}
	require.True(t, SameServers(servers, reversed))
	require.False(t, SameServers(servers, servers[:2]))
}
