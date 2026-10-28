package subscription

import (
	"strings"
	"testing"

	"github.com/podkop-net/podkop-experimental/src/backend/api"

	"github.com/stretchr/testify/require"
)

// testDecode reads links of the form "server|port|sni#name" as outbounds.
func testDecode(link string) ([]byte, []string, error) {
	fields := strings.Split(strings.Split(link, "#")[0], "|")
	return []byte(`{"type":"vless","tag":"x","server":"` + fields[0] + `","server_port":` + fields[1] + `,"tls":{"enabled":true,"server_name":"` + fields[2] + `"}}`), nil, nil
}

func server(name string, link string) Server {
	return Server{Name: name, Link: link + "#" + name, ID: link}
}

// The three kinds of change a provider makes, and the options of a server of a name that
// changed: renamed, the server of a name another one, taken out, put in.
func TestCompare(t *testing.T) {
	old := []Server{server("DE 113d", "de|443|a"), server("NL", "nl|443|a"), server("SE", "se|443|a"), server("FI", "fi|443|a")}
	fresh := []Server{server("DE 112d", "de|443|a"), server("NL", "nl|8443|b"), server("SE", "se|443|a"), server("PL", "pl|443|a")}
	require.Equal(t, api.ListChanges{Renamed: 1, Changed: 1, Removed: 1, Added: 1, Fields: []string{"server_port", "tls.server_name"}},
		Compare(old, fresh, testDecode))

	require.Equal(t, api.ListChanges{}, Compare(old, old, testDecode))
	// the same server twice under two names, one of them renamed
	twice := []Server{server("A", "a|1|x"), server("B", "a|1|x")}
	require.Equal(t, api.ListChanges{Renamed: 1}, Compare(twice, []Server{server("A", "a|1|x"), server("C", "a|1|x")}, testDecode))
	// a link that cannot be decoded is told apart by its text
	broken := []Server{{Name: "X", Link: "bad://1#X", Reason: "cannot be decoded"}}
	require.Equal(t, api.ListChanges{Changed: 1, Fields: []string{"link"}},
		Compare(broken, []Server{{Name: "X", Link: "bad://2#X", Reason: "cannot be decoded"}}, func(string) ([]byte, []string, error) { return nil, nil, errDecodeForTest }))
}

var errDecodeForTest = &decodeError{}

type decodeError struct{}

func (*decodeError) Error() string { return "cannot decode" }

// A list the provider only reordered is the same list; one with a name changed is not.
func TestSameList(t *testing.T) {
	list := []Server{server("A", "a|1|x"), server("B", "b|1|x")}
	require.True(t, SameList(list, []Server{list[1], list[0]}))
	require.False(t, SameList(list, []Server{list[0], server("C", "b|1|x")}))
	require.False(t, SameList(list, list[:1]))
}
