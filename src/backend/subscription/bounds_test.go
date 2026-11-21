package subscription

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/stretchr/testify/require"
)

// made is what the servers of a list take: their links, names, IDs, reasons, notes and outbounds.
func made(list List) int {
	total := 0
	for _, server := range list.Servers {
		total += len(server.Link) + len(server.Name) + len(server.ID) + len(server.Reason) + len(server.outbound)
		for _, note := range server.Notes {
			total += len(note)
		}
	}
	return total
}

// boundVless is a server outbound of the shapes of the bounds.
func boundVless(port int, extra string) string {
	return `{"protocol":"vless","settings":{"address":"a.example.net","port":` + strconv.Itoa(port) + `,"id":"c0ffee00-0000-4000-8000-000000000040"}` + extra + `}`
}

// A value one configuration shares among its servers (its remarks, the fragment of a dialer) is
// in each of them: the names are cut, the fragment is read as Xray reads it, and what the servers
// take stays within four times the body (and 256 KiB); past that the answer is refused.
func TestBoundsAmplification(t *testing.T) {
	t.Parallel()
	for _, shape := range [][2]int{{16 << 10, 250}, {32 << 10, 500}} {
		size, count := shape[0], shape[1]
		var outbounds strings.Builder
		for index := 0; index < count; index++ {
			outbounds.WriteString(boundVless(1000+index, `,"tag":"s`+strconv.Itoa(index)+`"`) + ",")
		}
		// a balancer over all of them: each is a server
		balancer := `"routing":{"balancers":[{"tag":"b","selector":["s"]}]}`
		body := `{"remarks":"` + strings.Repeat("R", size) + `","outbounds":[` + outbounds.String() + `{"protocol":"freedom","tag":"direct"}],` + balancer + `}`
		list, err := ParseList(context.Background(), []byte(body), realCodec)
		require.NoError(t, err)
		require.Len(t, list.Servers, count)
		for _, server := range list.Servers {
			require.Equal(t, maxName, utf8.RuneCountInString(server.Name))
			require.True(t, strings.HasSuffix(server.Name, "…"))
		}
		require.LessOrEqual(t, made(list), 4*len(body)+256<<10, "remarks %d × %d", size, count)

		outbounds.Reset()
		for index := 0; index < count; index++ {
			outbounds.WriteString(boundVless(1000+index, `,"tag":"s`+strconv.Itoa(index)+`","streamSettings":{"sockopt":{"dialerProxy":"f"}}`) + ",")
		}
		body = `{"outbounds":[` + outbounds.String() + `{"protocol":"freedom","tag":"f","settings":{"fragment":{"packets":"tlshello","length":"` + strings.Repeat("1", size) + `","interval":"1"}}}],` + balancer + `}`
		list, err = ParseList(context.Background(), []byte(body), realCodec)
		require.NoError(t, err)
		require.Len(t, list.Servers, count)
		require.Equal(t, "the fragment of the provider's dialer cannot be read", list.Servers[0].Reason)
		require.LessOrEqual(t, made(list), 4*len(body)+256<<10, "fragment %d × %d", size, count)
	}
	// a fragment of Xray's ranges is taken
	server := readOne(t, boundVless(443, `,"tag":"proxy","streamSettings":{"sockopt":{"dialerProxy":"f"}}}, {"protocol":"freedom","tag":"f","settings":{"fragment":{"packets":"1-3","length":100,"interval":"10-20","maxSplit":"2"}}`))
	require.True(t, server.Usable(), server.Reason)
	require.Equal(t, "1-3", outboundAt(t, server, "finalmask").(map[string]any)["tcp"].([]any)[0].(map[string]any)["packets"])
}

// The budget refuses an answer whose servers would take more than it allows, with a code and a
// text that hold no value.
func TestBoundsBudget(t *testing.T) {
	t.Parallel()
	limit := newBudget(1000)
	require.True(t, limit.spend(&Server{Link: strings.Repeat("l", 4000)}))
	require.True(t, limit.spend(&Server{Name: strings.Repeat("n", 256<<10)}))
	require.False(t, limit.spend(&Server{Notes: []string{"x"}}))
	failure := oversize()
	require.Equal(t, "oversize", failure.Code)
	require.True(t, failure.Final())
	var outbounds strings.Builder
	for index := 0; index < 3000; index++ {
		outbounds.WriteString(boundVless(1000+index, `,"tag":"s`+strconv.Itoa(index)+`"`) + ",")
	}
	body := `{"remarks":"` + strings.Repeat("😀", maxName) + `","outbounds":[` + outbounds.String() + `{"protocol":"freedom","tag":"direct"}],"routing":{"balancers":[{"selector":["s"]}]}}`
	reading := &reading{ctx: context.Background(), budget: &budget{left: len(body)}}
	servers, _, _ := readXray(reading, []json.RawMessage{json.RawMessage(body)}, realDecode)
	require.Nil(t, servers)
	require.Equal(t, "oversize", reading.failure.Code)
}

// Shapes that once took time quadratic in their size: thousands of keys of an outbound, headers,
// settings of XHTTP, prefixes of selectors, options of sing-box. Each is read in a bounded time.
func TestBoundsTime(t *testing.T) {
	t.Parallel()
	const count = 40000
	keys := func(prefix string, value string, separator bool) string {
		var text strings.Builder
		for index := 0; index < count; index++ {
			if separator || index > 0 {
				text.WriteString(",")
			}
			name, suffix, _ := strings.Cut(prefix, "*")
			text.WriteString(`"` + name + strconv.Itoa(1000000+index) + suffix + `":` + value)
		}
		return text.String()
	}
	// unknown protocols: a reason each, no decoding; one prefix written count times
	var unknown, prefixes strings.Builder
	for index := 0; index < 2*count; index++ {
		unknown.WriteString(`{"protocol":"x"},`)
		if index > 0 {
			prefixes.WriteString(",")
		}
		prefixes.WriteString(`"b"`)
	}
	// each shape, and what it took before: notes and keys looked for by a scan of every key of
	// an object (2 to 30 s on nexus), the prefixes for each outbound (5 s)
	for _, shape := range []struct {
		name string
		body string
		most time.Duration
	}{
		{"outbound keys", "[" + xrayConfigOf("R", boundVless(443, `,"tag":"proxy"`+keys("k", "0", true))) + "]", time.Second},
		{"ws headers", "[" + xrayConfigOf("R", boundVless(443, `,"tag":"proxy","streamSettings":{"network":"ws","wsSettings":{"path":"/","headers":{`+keys("h", `"v"`, false)+`}}}`)) + "]", 8 * time.Second},
		{"xhttp keys", "[" + xrayConfigOf("R", boundVless(443, `,"tag":"proxy","streamSettings":{"network":"xhttp","security":"tls","xhttpSettings":{"path":"/"`+keys("x", "0", true)+`}}`)) + "]", time.Second},
		{"prefixes", `{"outbounds":[` + unknown.String() + `{"protocol":"freedom","tag":"direct"}],"routing":{"balancers":[{"tag":"b","selector":[` + prefixes.String() + `]}]}}`, 2 * time.Second},
		{"sing-box paths", `{"outbounds":[{"type":"vless","tag":"s","server":"a.example.net","server_port":443,"uuid":"c0ffee00-0000-4000-8000-000000000040"` +
			keys("a*_path", "0", true) + `}]}`, time.Second},
		{"sing-box headers", `{"outbounds":[{"type":"vless","tag":"s","server":"a.example.net","server_port":443,"uuid":"c0ffee00-0000-4000-8000-000000000040","transport":{"type":"ws","headers":{` +
			keys("h", `"v"`, false) + `}}}]}`, 8 * time.Second},
	} {
		started := time.Now()
		_, err := ParseList(context.Background(), []byte(shape.body), realCodec)
		t.Logf("%s: %v (%v)", shape.name, time.Since(started).Round(time.Millisecond), err)
		if took := time.Since(started); took > shape.most {
			t.Errorf("%s took %v, more than %v", shape.name, took.Round(time.Millisecond), shape.most)
		}
	}
	// a balancer's prefixes select as Xray's do: by a prefix, the shortest standing for the rest
	config := &xrayConfig{prefixes: shortestPrefixes([]string{"eu-de", "eu-", "us", "usa-1", "x"})}
	require.Equal(t, []string{"eu-", "us", "x"}, config.prefixes)
	for tag, selected := range map[string]bool{"eu-": true, "eu-fr": true, "eu": false, "us": true, "usa-1": true, "u": false, "x1": true, "w": false, "": false, "zz": false} {
		require.Equal(t, selected, config.selects(tag), tag)
	}
}

// The names of sing-box's options are read as encoding/json reads them, folded: domain_reſolver
// is domain_resolver, and is left out with its note as that one is; so are Xray's keys.
func TestBoundsFoldedNames(t *testing.T) {
	t.Parallel()
	for written, note := range map[string]string{"domain_reſolver": "domain_resolver", "netnſ": "netns", "routing_marK": "routing_mark", "Bind_Interface": "bind_interface", "reuſe_addr": "reuse_addr"} {
		list, err := ParseList(context.Background(), []byte(`{"outbounds":[{"type":"vless","tag":"s","server":"a.example.net","server_port":443,"uuid":"c0ffee00-0000-4000-8000-000000000041",`+strconv.Quote(written)+`:"x"}]}`), realCodec)
		require.NoError(t, err)
		server := list.Servers[0]
		require.True(t, server.Usable(), "%s: %s", written, server.Reason)
		require.Equal(t, []string{note + " is a setting of the provider's app and is left out"}, server.Notes, written)
	}
	require.Equal(t, "domain_resolver", fold("Domain_Reſolver"))
	require.Equal(t, "mark", fold("marK"))
	quiet := readOne(t, boundVless(443, `,"tag":"proxy","streamSettings":{"network":"tcp","sockopt":{"interface":"lo","marK":5}}`))
	require.Empty(t, quiet.Notes, "Xray's keys folded too")
}

// The end of the download stops the reading of a long list: a canceled context, a deadline.
func TestBoundsContext(t *testing.T) {
	t.Parallel()
	var configs []string
	for index := 0; index < 2000; index++ {
		configs = append(configs, xrayConfigOf("S"+strconv.Itoa(index), boundVless(1000+index, `,"tag":"proxy"`)))
	}
	body := []byte("[" + strings.Join(configs, ",") + "]")
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := ParseList(canceled, body, realCodec)
	require.Equal(t, "canceled", err.(*Failure).Code)
	var links strings.Builder
	for index := 0; index < 5000; index++ {
		links.WriteString("vless://c0ffee00-0000-4000-8000-000000000042@a.example.net:" + strconv.Itoa(1000+index) + "?security=none#S\n")
	}
	_, err = ParseList(canceled, []byte(links.String()), realCodec)
	require.Equal(t, "canceled", err.(*Failure).Code)
	deadline, stop := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer stop()
	started := time.Now()
	_, err = ParseList(deadline, body, realCodec)
	if err != nil {
		require.Equal(t, "canceled", err.(*Failure).Code)
	}
	require.Less(t, time.Since(started), 5*time.Second)
	// the control: the same body is read with time to read it
	list, err := ParseList(context.Background(), body, realCodec)
	require.NoError(t, err)
	require.Len(t, list.Servers, 2000)
}
