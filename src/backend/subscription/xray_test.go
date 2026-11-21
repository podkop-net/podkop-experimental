package subscription

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// xrayConfigOf is a configuration of Xray JSON with one outbound tagged proxy beside freedom.
func xrayConfigOf(remarks string, outbound string) string {
	return `{"remarks":` + strconv.Quote(remarks) + `,"outbounds":[` + outbound + `,{"tag":"direct","protocol":"freedom"}]}`
}

// readOne reads Xray JSON of one configuration and gives its one server.
func readOne(t *testing.T, outbound string) Server {
	t.Helper()
	list, err := ParseList(context.Background(), []byte("["+xrayConfigOf("R", outbound)+"]"), realCodec)
	require.NoError(t, err)
	require.Len(t, list.Servers, 1)
	return list.Servers[0]
}

// paramsOf are the parameters of a link podkop made.
func paramsOf(t *testing.T, link string) url.Values {
	t.Helper()
	_, query, _ := strings.Cut(link, "?")
	query, _, _ = strings.Cut(query, "#")
	values, err := url.ParseQuery(query)
	require.NoError(t, err, link)
	return values
}

// outboundAt is the value of an option of the decoded outbound at a path.
func outboundAt(t *testing.T, server Server, path string) any {
	t.Helper()
	var tree any
	require.NoError(t, json.Unmarshal(server.outbound, &tree))
	for _, key := range strings.Split(path, ".") {
		node, isObject := tree.(map[string]any)
		if !isObject {
			return nil
		}
		tree = node[key]
	}
	return tree
}

// The format comes from the body: a list of configurations, one configuration of Xray, one of
// sing-box; JSON of neither is refused, a configuration with no server has no servers.
func TestFormatDetection(t *testing.T) {
	t.Parallel()
	vless := `{"tag":"proxy","protocol":"vless","settings":{"address":"a.example.net","port":443,"id":"c0ffee00-0000-4000-8000-000000000001"}}`
	single := xrayConfigOf("One", vless)
	singBox := `{"outbounds":[{"type":"vless","tag":"S","server":"a.example.net","server_port":443,"uuid":"c0ffee00-0000-4000-8000-000000000001"},{"type":"direct","tag":"direct"}]}`
	for body, want := range map[string]struct {
		format  string
		configs int
		code    string
	}{
		"[" + single + "]":                {FormatXray, 1, ""},
		"[" + single + "," + single + "]": {FormatXray, 2, ""},
		single:                            {FormatXray, 1, ""},
		singBox:                           {FormatSingBox, 0, ""},
		"\ufeff  " + single + "\n":        {FormatXray, 1, ""},
		base64.StdEncoding.EncodeToString([]byte(single)):     {FormatXray, 1, ""},
		base64.RawURLEncoding.EncodeToString([]byte(singBox)): {FormatSingBox, 0, ""},
		"[]":                               {"", 0, "nolinks"},
		`[{"remarks":"x","outbounds":[]}]`: {"", 0, "nolinks"},
		xrayConfigOf("Only direct", `{"tag":"block","protocol":"blackhole"}`):                {"", 0, "nolinks"},
		`{"outbounds":[{"type":"selector","tag":"proxy","outbounds":[]},{"type":"direct"}]}`: {"", 0, "nolinks"},
		`[1,2,3]`:                           {"", 0, "json"},
		`{"version":1}`:                     {"", 0, "json"},
		`{"outbounds":{}}`:                  {"", 0, "json"},
		`{"outbounds":[{"name":"x"}]}`:      {"", 0, "json"},
		`{"outbounds":[{"protocol"`:         {"", 0, "json"},
		`[{"outbounds":[` + vless + `]},5]`: {FormatXray, 1, ""},
	} {
		list, err := ParseList(context.Background(), []byte(body), realCodec)
		if want.code != "" {
			require.Error(t, err, body)
			require.Equal(t, want.code, err.(*Failure).Code, body)
			continue
		}
		require.NoError(t, err, body)
		require.Equal(t, want.format, list.Format, body)
		require.Equal(t, want.configs, list.Configs, body)
		require.NotEmpty(t, list.Servers, body)
	}
}

// The texts of the refusals of the formats hold no value of the body.
func TestFormatRefusalTexts(t *testing.T) {
	t.Parallel()
	_, err := ParseList(context.Background(), []byte(`{"secret-key":"VALUE-1234"}`), realCodec)
	require.Equal(t, "the provider sent JSON that is not a configuration of Xray or sing-box", err.Error())
	_, err = ParseList(context.Background(), []byte("proxies:\n  - name: SECRET\n"), realCodec)
	require.Equal(t, "clash", err.(*Failure).Code)
	require.NotContains(t, err.Error(), "SECRET")
	require.Contains(t, err.Error(), "which podkop does not read")
}

// A list of links Happ alone reads (happ://crypt…) is refused with a code of its own; beside a
// real link it is skipped as before.
func TestHappCrypt(t *testing.T) {
	t.Parallel()
	_, err := ParseList(context.Background(), []byte("happ://crypt3/SECRETDATA\nhapp://crypt4/MORE\n"), Codec{Decode: fakeDecode})
	require.Equal(t, "happ-crypt", err.(*Failure).Code)
	require.NotContains(t, err.Error(), "SECRETDATA")
	encoded := base64.StdEncoding.EncodeToString([]byte("happ://crypt/x\n"))
	_, err = ParseList(context.Background(), []byte(encoded), Codec{Decode: fakeDecode})
	require.Equal(t, "happ-crypt", err.(*Failure).Code)
	list, err := ParseList(context.Background(), []byte("happ://crypt3/x\nvless://u@a.example:443#A\n"), Codec{Decode: fakeDecode})
	require.NoError(t, err)
	require.Len(t, list.Servers, 1)
	_, err = ParseList(context.Background(), []byte("happ://routing/onadd/x\n"), Codec{Decode: fakeDecode})
	require.Equal(t, "nolinks", err.(*Failure).Code, "only the encrypted links tell Happ's")
}

// A server that comes as a link of the provider and in its Xray JSON is the same server: the
// same ID, so its cures and verdicts stay when the format changes.
func TestXrayIDsOfTheLinks(t *testing.T) {
	t.Parallel()
	const uuid = "c0ffee00-0000-4000-8000-000000000002"
	const key = "jYM97hnBoGvH3Wyf0ExRqCn75nTpzcUVIVb0_q18RvY"
	const pin = "0458d1060b5385cfda9a8db103896253318203af84ed7c547ec763e7c0d80928"
	for name, pair := range map[string][2]string{
		"reality vision": {
			`{"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"r.example.net","port":443,"users":[{"id":"` + uuid + `","encryption":"none","flow":"xtls-rprx-vision"}]}]},
			  "streamSettings":{"network":"tcp","tcpSettings":{},"security":"reality","realitySettings":{"serverName":"www.example.com","fingerprint":"chrome","publicKey":"` + key + `","shortId":"0123"}}}`,
			"vless://" + uuid + "@r.example.net:443?encryption=none&flow=xtls-rprx-vision&type=tcp&security=reality&sni=www.example.com&fp=chrome&pbk=" + key + "&sid=0123#R",
		},
		"trojan ws tls": {
			`{"tag":"proxy","protocol":"trojan","settings":{"servers":[{"address":"t.example.net","port":443,"password":"p-1"}]},
			  "streamSettings":{"network":"ws","wsSettings":{"path":"/w","host":"t.example.net","headers":{}},"security":"tls","tlsSettings":{"serverName":"t.example.net","fingerprint":"chrome","alpn":["http/1.1"]}}}`,
			"trojan://p-1@t.example.net:443?type=ws&path=%2Fw&host=t.example.net&security=tls&sni=t.example.net&fp=chrome&alpn=http%2F1.1#R",
		},
		"shadowsocks 2022": {
			`{"tag":"proxy","protocol":"shadowsocks","settings":{"servers":[{"address":"s.example.net","port":8388,"method":"2022-blake3-aes-128-gcm","password":"eRF55dk0knx0Gh7vxabNGQ=="}]},"streamSettings":{"network":"tcp"}}`,
			"ss://" + base64.StdEncoding.EncodeToString([]byte("2022-blake3-aes-128-gcm:eRF55dk0knx0Gh7vxabNGQ==")) + "@s.example.net:8388#R",
		},
		"hysteria2 salamander pinned": {
			`{"tag":"proxy","protocol":"hysteria","settings":{"address":"h.example.net","port":443,"version":2},
			  "streamSettings":{"network":"hysteria","hysteriaSettings":{"version":2,"auth":"a-1"},"security":"tls","tlsSettings":{"serverName":"h.example.net","fingerprint":"chrome","alpn":["h3"],"pinnedPeerCertSha256":"` + pin + `"},
			  "finalmask":{"udp":[{"type":"salamander","settings":{"password":"o-1"}}]}}}`,
			"hysteria2://a-1@h.example.net:443/?obfs=salamander&obfs-password=o-1&sni=h.example.net&pinSHA256=" + pin + "#R",
		},
		"xhttp extra": {
			`{"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"x.example.net","port":443,"users":[{"id":"` + uuid + `","encryption":"none"}]}]},
			  "streamSettings":{"network":"xhttp","xhttpSettings":{"mode":"packet-up","host":"x.example.net","path":"/x","extra":{"xPaddingBytes":"100-1000","xmux":{"maxConcurrency":"16-32"}}},"security":"tls","tlsSettings":{"serverName":"x.example.net","alpn":["h2"]}}}`,
			"vless://" + uuid + "@x.example.net:443?encryption=none&type=xhttp&path=%2Fx&host=x.example.net&mode=packet-up&extra=" + url.QueryEscape(`{"xPaddingBytes":"100-1000","xmux":{"maxConcurrency":"16-32"}}`) + "&security=tls&sni=x.example.net&alpn=h2#R",
		},
	} {
		fromJSON := readOne(t, pair[0])
		fromLink := parseLink(pair[1], 1, realDecode)
		require.True(t, fromJSON.Usable(), "%s: %s", name, fromJSON.Reason)
		require.True(t, fromLink.Usable(), "%s: %s", name, fromLink.Reason)
		require.Equal(t, string(fromLink.outbound), string(fromJSON.outbound), name)
		require.Equal(t, fromLink.ID, fromJSON.ID, name)
		require.Equal(t, "R", fromJSON.Name, name)
	}
	// the control: another short id is another server
	first := readOne(t, `{"tag":"proxy","protocol":"vless","settings":{"address":"r.example.net","port":443,"id":"`+uuid+`"},"streamSettings":{"security":"reality","realitySettings":{"publicKey":"`+key+`","shortId":"01"}}}`)
	second := readOne(t, `{"tag":"proxy","protocol":"vless","settings":{"address":"r.example.net","port":443,"id":"`+uuid+`"},"streamSettings":{"security":"reality","realitySettings":{"publicKey":"`+key+`","shortId":"02"}}}`)
	require.NotEqual(t, first.ID, second.ID)
}

// Each key of an outbound is mapped to its parameter of the link (the rows of the mapping).
func TestXrayMapping(t *testing.T) {
	t.Parallel()
	const uuid = "c0ffee00-0000-4000-8000-000000000003"
	vless := func(stream string) string {
		return `{"tag":"proxy","protocol":"vless","settings":{"address":"m.example.net","port":443,"id":"` + uuid + `"},"streamSettings":` + stream + `}`
	}
	for _, row := range []struct {
		name     string
		outbound string
		params   map[string]string
		absent   []string
		options  map[string]any
	}{
		{"vless encryption none by default", vless(`{}`), map[string]string{"encryption": "none", "security": "none"}, []string{"flow"}, nil},
		{"raw is tcp", vless(`{"network":"raw"}`), map[string]string{"type": "tcp"}, nil, nil},
		{"method names the network", vless(`{"method":"ws","network":"tcp"}`), map[string]string{"type": "ws"}, nil, nil},
		{"tls", vless(`{"security":"tls","tlsSettings":{"serverName":"s.example.net","alpn":"h2,http/1.1","fingerprint":"firefox","allowInsecure":true}}`),
			map[string]string{"security": "tls", "sni": "s.example.net", "alpn": "h2,http/1.1", "fp": "firefox", "allowInsecure": "1"}, nil,
			map[string]any{"tls.insecure": true}},
		{"tls pins and names", vless(`{"security":"tls","tlsSettings":{"serverName":"s.example.net","pinnedPeerCertSha256":"0458d1060b5385cfda9a8db103896253318203af84ed7c547ec763e7c0d80928","verifyPeerCertByName":"a.example.net,b.example.net"}}`),
			map[string]string{"pcs": "0458d1060b5385cfda9a8db103896253318203af84ed7c547ec763e7c0d80928", "vcn": "a.example.net,b.example.net"}, nil,
			map[string]any{"tls.certificate_server_name": []any{"a.example.net", "b.example.net"}}},
		{"tls root of the configuration", vless(`{"security":"tls","tlsSettings":{"certificates":[{"usage":"verify","certificate":["-----BEGIN CERTIFICATE-----","MIIB","-----END CERTIFICATE-----"]}]}}`),
			map[string]string{"cert": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"}, nil, nil},
		{"reality", vless(`{"security":"reality","realitySettings":{"serverName":"w.example.com","publicKey":"jYM97hnBoGvH3Wyf0ExRqCn75nTpzcUVIVb0_q18RvY","shortId":"0a","spiderX":"/p","mldsa65Verify":"k","fingerprint":"safari"}}`),
			map[string]string{"security": "reality", "sni": "w.example.com", "pbk": "jYM97hnBoGvH3Wyf0ExRqCn75nTpzcUVIVb0_q18RvY", "sid": "0a", "spx": "/p", "pqv": "k", "fp": "safari"}, nil, nil},
		{"ws", vless(`{"network":"ws","wsSettings":{"path":"/w?ed=2048","host":"h.example.net","heartbeatPeriod":15,"headers":{"User-Agent":"UA","Host":"other.example.net"}}}`),
			map[string]string{"type": "ws", "path": "/w?ed=2048", "host": "h.example.net", "heartbeatPeriod": "15", "sb.transport.headers.User-Agent": "UA"}, nil,
			map[string]any{"transport.max_early_data": float64(2048), "transport.headers.Host": "h.example.net"}},
		{"grpc", vless(`{"network":"grpc","grpcSettings":{"serviceName":"g","authority":"a.example.net"}}`),
			map[string]string{"type": "grpc", "serviceName": "g", "mode": "gun", "authority": "a.example.net"}, nil, nil},
		{"xhttp settings without extra", vless(`{"network":"xhttp","xhttpSettings":{"path":"/x","mode":"auto","noSSEHeader":true}}`),
			map[string]string{"type": "xhttp", "path": "/x", "mode": "auto", "extra": `{"noSSEHeader":true}`}, nil, nil},
		{"sockopt fast open", vless(`{"sockopt":{"tcpFastOpen":true}}`), map[string]string{"tfo": "1"}, nil, map[string]any{"tcp_fast_open": true}},
		{"sockopt fast open off", vless(`{"sockopt":{"tcpFastOpen":-1}}`), nil, []string{"tfo"}, nil},
		{"finalmask", vless(`{"finalmask":{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","length":"100-200"}}]}}`),
			map[string]string{"fm": `{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","length":"100-200"}}]}`}, nil, nil},
		{"vmess security", `{"tag":"proxy","protocol":"vmess","settings":{"vnext":[{"address":"v.example.net","port":1,"users":[{"id":"` + uuid + `","security":"aes-128-gcm","alterId":64}]}]}}`,
			map[string]string{"encryption": "aes-128-gcm"}, []string{"aid", "alterId"}, map[string]any{"alter_id": nil}},
		{"socks without user", `{"tag":"proxy","protocol":"socks","settings":{"servers":[{"address":"198.51.100.1","port":1080}]}}`, nil, []string{"security", "type"}, nil},
	} {
		server := readOne(t, row.outbound)
		require.True(t, server.Usable(), "%s: %s", row.name, server.Reason)
		params := paramsOf(t, server.Link)
		for key, value := range row.params {
			require.Equal(t, value, params.Get(key), "%s: %s", row.name, key)
		}
		for _, key := range row.absent {
			require.False(t, params.Has(key), "%s: %s", row.name, key)
		}
		for path, value := range row.options {
			require.Equal(t, value, outboundAt(t, server, path), "%s: %s", row.name, path)
		}
	}
}

// Every key of an outbound is mapped, left out by the reviewed lists, or named in a note:
// nothing is dropped without a word.
func TestXrayNothingSilent(t *testing.T) {
	t.Parallel()
	server := readOne(t, `{"tag":"proxy","protocol":"vless","odd1":1,
		"settings":{"vnext":[{"address":"n.example.net","port":443,"odd2":1,"users":[{"id":"c0ffee00-0000-4000-8000-000000000004","odd3":1}]}],"odd4":1},
		"streamSettings":{"network":"ws","odd5":1,"security":"tls","tlsSettings":{"odd6":1},"wsSettings":{"odd7":1},"sockopt":{"odd8":1},"finalmask":{"odd9":1}},
		"mux":{"odd10":1},"proxySettings":{"odd11":1}}`)
	require.True(t, server.Usable(), server.Reason)
	for _, path := range []string{"odd1", "settings.vnext.odd2", "settings.vnext.users.odd3", "settings.odd4", "streamSettings.odd5", "streamSettings.tlsSettings.odd6",
		"streamSettings.wsSettings.odd7", "streamSettings.sockopt.odd8", "streamSettings.finalmask.odd9", "mux.odd10", "proxySettings.odd11"} {
		require.True(t, containsPart(server.Notes, path+" is not supported and is ignored"), "%s in %q", path, server.Notes)
	}
	// the reviewed lists say why each key is left out
	for _, list := range []map[string]string{xrayOutboundSilent, xrayUserSilent, xrayShadowsocksSilent, xrayTLSSilent, xrayREALITYSilent, xraySockoptSilent,
		xrayAcceptSilent, xrayGRPCSilent, xrayHTTPSilent, xrayHysteriaSilent, xrayMuxSilent, xrayQUICSilent, xrayFreedomSilent, xrayFreedomSockoptSilent} {
		for key, why := range list {
			require.Equal(t, strings.ToLower(key), key)
			require.NotEmpty(t, why, key)
		}
	}
	// the keys of the client: a note that they are the app's
	client := readOne(t, `{"tag":"proxy","protocol":"vless","settings":{"address":"n.example.net","port":443,"id":"c0ffee00-0000-4000-8000-000000000004"},
		"streamSettings":{"security":"tls","tlsSettings":{"echForceQuery":"full","disableSystemRoot":true}}}`)
	require.Contains(t, client.Notes, "streamSettings.tlsSettings.echForceQuery is a setting of the provider's app and is left out")
	require.Contains(t, client.Notes, "streamSettings.tlsSettings.disableSystemRoot is a setting of the provider's app and is left out")
	// what the app alone uses is left out without a note
	quiet := readOne(t, `{"tag":"proxy","protocol":"vless","sendThrough":"192.0.2.1","targetStrategy":"UseIPv4",
		"settings":{"vnext":[{"address":"q.example.net","port":443,"users":[{"id":"c0ffee00-0000-4000-8000-000000000005","encryption":"none","level":0,"email":"e@example.org"}]}]},
		"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"q.example.net","enableSessionResumption":true,"minVersion":"1.2"},"sockopt":{"mark":255,"interface":"wan","domainStrategy":"UseIP","tcpKeepAliveIdle":30}},
		"mux":{"enabled":false,"concurrency":8}}`)
	require.Empty(t, quiet.Notes)
}

// The servers of a configuration: the proxy, the members of its balancers and the targets of its
// rules; with none, every server outbound but the relays of others. A server is listed once by
// (ID, name); one under two names stays two.
func TestXraySelection(t *testing.T) {
	t.Parallel()
	server := func(tag string, host string) string {
		return `{"tag":"` + tag + `","protocol":"vless","settings":{"address":"` + host + `","port":443,"id":"c0ffee00-0000-4000-8000-000000000006"}}`
	}
	relayed := func(tag string, host string, relay string) string {
		return `{"tag":"` + tag + `","protocol":"vless","settings":{"address":"` + host + `","port":443,"id":"c0ffee00-0000-4000-8000-000000000006"},"streamSettings":{"sockopt":{"dialerProxy":"` + relay + `"}}}`
	}
	names := func(body string) []string {
		list, err := ParseList(context.Background(), []byte(body), realCodec)
		require.NoError(t, err, body)
		var found []string
		for _, server := range list.Servers {
			found = append(found, server.Name)
		}
		return found
	}
	// balancer members by prefix, the fallback, a rule's target; not the other outbound. The tags
	// are the configuration's own: its servers take its remarks (the plan numbers them)
	require.Equal(t, []string{"R", "R", "R", "R", "R"}, names(`{"remarks":"R","outbounds":[`+server("proxy", "p.example.net")+`,`+server("eu-1", "a.example.net")+`,`+
		server("eu-2", "b.example.net")+`,`+server("backup", "c.example.net")+`,`+server("routed", "d.example.net")+`,`+server("other", "e.example.net")+`],
		"routing":{"balancers":[{"tag":"b","selector":["eu-"],"fallbackTag":"backup"}],"rules":[{"outboundTag":"routed"},{"outboundTag":"direct"}]}}`))
	// no routing: the default outbound, the first, is the one Xray uses
	require.Equal(t, []string{"R"}, names(`{"remarks":"R","outbounds":[`+relayed("first", "a.example.net", "relay")+`,`+server("second", "b.example.net")+`,`+server("relay", "r.example.net")+`]}`))
	// none Xray uses is a server (the first is no server): every server but a relay of another
	require.Equal(t, []string{"R", "R"}, names(`{"remarks":"R","outbounds":[{"tag":"direct","protocol":"freedom"},`+relayed("first", "a.example.net", "relay")+`,`+server("second", "b.example.net")+`,`+server("relay", "r.example.net")+`]}`))
	// its only server takes the remarks
	require.Equal(t, []string{"R"}, names(`{"remarks":"R","outbounds":[`+relayed("first", "a.example.net", "relay")+`,`+server("relay", "r.example.net")+`]}`))
	// no remarks: the tag; neither: the number
	require.Equal(t, []string{"R", "R"}, names(`{"remarks":"R","outbounds":[`+server("proxy", "a.example.net")+`,`+server("proxy-2", "b.example.net")+`],"routing":{"balancers":[{"selector":["proxy"]}]}}`))
	require.Equal(t, []string{"server 1"}, names(`{"outbounds":[`+server("", "a.example.net")+`]}`))
	require.Equal(t, []string{"proxy", "eu"}, names(`{"outbounds":[`+server("proxy", "a.example.net")+`,`+server("eu", "b.example.net")+`],"routing":{"rules":[{"outboundTag":"eu"}]}}`))
	// the same server in two configurations under one name: once; under two names: twice
	one := `{"remarks":"Same","outbounds":[` + server("proxy", "a.example.net") + `]}`
	other := `{"remarks":"Other","outbounds":[` + server("proxy", "a.example.net") + `]}`
	require.Equal(t, []string{"Same"}, names("["+one+","+one+"]"))
	require.Equal(t, []string{"Same", "Other"}, names("["+one+","+other+"]"))
	// a member that is the main server of another configuration is that one's entry, where that
	// one is
	withExit := `{"remarks":"A","outbounds":[` + server("proxy", "a.example.net") + `,` + server("exit", "b.example.net") + `],"routing":{"balancers":[{"selector":["proxy","exit"]}]}}`
	exit := `{"remarks":"B","outbounds":[` + server("proxy", "b.example.net") + `]}`
	require.Equal(t, []string{"A", "B"}, names("["+withExit+","+exit+"]"))
	require.Equal(t, []string{"B", "A"}, names("["+exit+","+withExit+"]"))
	// the main server without a proxy: the one server all the servers of the configuration are
	variants := `{"remarks":"V","outbounds":[` + server("V-DIRECT", "v.example.net") + `,` + relayed("V-VIA", "v.example.net", "relay") + `,` + server("relay", "r.example.net") + `]}`
	group := `{"remarks":"Group","outbounds":[` + server("V-DIRECT", "v.example.net") + `,` + server("W-DIRECT", "w.example.net") + `],"routing":{"balancers":[{"selector":["V-","W-"]}]}}`
	require.Equal(t, []string{"Group", "V"}, names("["+group+","+variants+"]"), "a group has no main server; W is listed in it alone")
}

// Remnawave's configurations of locations (a server DIRECT and VIA a relay in a balancer, the
// relay only a dialerProxy target), of a group (a balancer over the servers of locations) and of
// the relay alone: one entry a server, named by its location, the chain noted only for a server
// the provider lists chained alone.
func TestXrayLocations(t *testing.T) {
	t.Parallel()
	body, err := os.ReadFile("testdata/xray/locations.json")
	require.NoError(t, err)
	list, err := ParseList(context.Background(), body, realCodec)
	require.NoError(t, err)
	require.Equal(t, 7, list.Configs)
	var names []string
	ids := map[string]bool{}
	for _, server := range list.Servers {
		names = append(names, server.Name)
		require.True(t, server.Usable(), server.Name)
		require.False(t, ids[server.ID], "%s: each server once", server.Name)
		ids[server.ID] = true
		require.True(t, strings.HasSuffix(server.Link, "#"+url.PathEscape(server.Name)), "%s: the link has the name", server.Name)
		if server.Name == "🇳🇱 Netherlands via Russia" {
			require.Equal(t, []string{"the provider connects it through RU_1_EXIT; podkop connects it directly"}, server.Notes)
		} else {
			require.Empty(t, server.Notes, server.Name)
		}
	}
	require.Equal(t, []string{"🇩🇪 Germany", "🇸🇪 Sweden", "🇪🇪 Estonia", "🇵🇱 Poland", "🇷🇺 Russia", "🇳🇱 Netherlands via Russia"}, names)
}

// The chains of the provider are notes: the server is connected directly.
func TestXrayChainNotes(t *testing.T) {
	t.Parallel()
	list, err := ParseList(context.Background(), []byte(`{"remarks":"Exit","outbounds":[
		{"tag":"proxy","protocol":"vless","settings":{"address":"e.example.net","port":443,"id":"c0ffee00-0000-4000-8000-000000000007"},"streamSettings":{"sockopt":{"dialerProxy":"🔒 Relay"}}},
		{"tag":"🔒 Relay","protocol":"vless","settings":{"address":"r.example.net","port":443,"id":"c0ffee00-0000-4000-8000-000000000008"}}]}`), realCodec)
	require.NoError(t, err)
	require.Len(t, list.Servers, 1)
	require.Equal(t, []string{"the provider connects it through 🔒 Relay; podkop connects it directly"}, list.Servers[0].Notes)
	require.Equal(t, "Exit", list.Servers[0].Name)
	require.Nil(t, outboundAt(t, list.Servers[0], "detour"))
	// the older form of the cut of the hello: a freedom dialer with a fragment
	list, err = ParseList(context.Background(), []byte(`{"remarks":"F","outbounds":[
		{"tag":"proxy","protocol":"vless","settings":{"address":"f.example.net","port":443,"id":"c0ffee00-0000-4000-8000-000000000009"},"streamSettings":{"security":"tls","sockopt":{"dialerProxy":"fragment"}}},
		{"tag":"fragment","protocol":"freedom","settings":{"fragment":{"packets":"tlshello","length":"100-200"}}}]}`), realCodec)
	require.NoError(t, err)
	require.Empty(t, list.Servers[0].Notes)
	require.Equal(t, "tlshello", outboundAt(t, list.Servers[0], "finalmask").(map[string]any)["tcp"].([]any)[0].(map[string]any)["packets"])
}

// No note, reason, failure or log line repeats a value of the configuration: the IDs, the
// passwords, the keys, the short ids, the addresses.
func TestFormsKeepSecrets(t *testing.T) {
	t.Parallel()
	secrets := []string{"c0ffee00-0000-4000-8000-00000000f0", "fixture-", "jYM97hnBoGvH3Wyf0ExRqCn75nTpzcUVIVb0_q18RvY", "KbGYQL56K1aLeair9OW", "0123abcd", "eRF55dk0knx0Gh7vxab",
		".example.net", "203.0.113.", "198.51.100.", "0458d1060b5385cf", "AEL+DQA+KgAgACDi", "mlkem768x25519plus.native"}
	var files []string
	for _, pattern := range []string{"testdata/xray/*.json", "testdata/singbox/*.json", "testdata/remnawave/*/xray.json", "testdata/remnawave/*/singbox.json"} {
		found, err := filepath.Glob(pattern)
		require.NoError(t, err)
		files = append(files, found...)
	}
	require.NotEmpty(t, files)
	for _, file := range files {
		body, err := os.ReadFile(file)
		require.NoError(t, err)
		list, err := ParseList(context.Background(), body, realCodec)
		var texts []string
		if err != nil {
			texts = append(texts, err.Error())
		}
		for _, server := range list.Servers {
			texts = append(texts, server.Reason)
			texts = append(texts, server.Notes...)
		}
		for _, text := range texts {
			for _, secret := range secrets {
				require.NotContains(t, text, secret, file)
			}
		}
	}
}

// A body as large as a list may be is read in a bounded time; nesting, wrong types and values of
// other types are refused or give reasons, never a panic.
func TestFormsRobust(t *testing.T) {
	t.Parallel()
	var configs []string
	size := 0
	for index := 0; size < MaxBody-4096; index++ {
		config := xrayConfigOf("Server "+strconv.Itoa(index), `{"tag":"proxy","protocol":"vless","settings":{"address":"s`+strconv.Itoa(index)+`.example.net","port":443,"id":"c0ffee00-0000-4000-8000-000000000010"},
			"streamSettings":{"network":"ws","security":"tls","tlsSettings":{"serverName":"s.example.net"},"wsSettings":{"path":"/`+strings.Repeat("p", 512)+`"}}}`)
		configs = append(configs, config)
		size += len(config) + 1
	}
	body := "[" + strings.Join(configs, ",") + "]"
	require.LessOrEqual(t, len(body), MaxBody)
	started := time.Now()
	list, err := ParseList(context.Background(), []byte(body), realCodec)
	require.NoError(t, err)
	require.Equal(t, len(configs), list.Configs)
	require.Len(t, list.Servers, len(configs))
	require.Less(t, time.Since(started), 60*time.Second)

	deep := strings.Repeat(`{"outbounds":[`, 1000) + strings.Repeat(`]}`, 1000)
	_, err = ParseList(context.Background(), []byte(deep), realCodec)
	require.Error(t, err)
	deeper := strings.Repeat("[", 20000) + strings.Repeat("]", 20000)
	_, err = ParseList(context.Background(), []byte(deeper), realCodec)
	require.Equal(t, "json", err.(*Failure).Code)
	for _, body := range []string{
		`{"outbounds":[{"protocol":"vless","tag":"proxy","settings":[]}]}`,
		`{"outbounds":[{"protocol":"vless","tag":"proxy","settings":{"address":5,"port":"x"}}]}`,
		`{"outbounds":[{"protocol":"vless","tag":"proxy","settings":{"address":"a.example.net","port":1,"id":"c0ffee00-0000-4000-8000-000000000011"},"streamSettings":"x"}]}`,
		`{"outbounds":[{"protocol":"vless","tag":"proxy","settings":{"vnext":"x"}}]}`,
		`{"outbounds":[{"protocol":"hysteria","tag":"proxy","settings":{"version":"2","address":"a.example.net","port":1},"streamSettings":{"network":"hysteria","security":"tls","finalmask":{"udp":"x","quicParams":5}}}]}`,
		`{"outbounds":[{"protocol":["vless"],"tag":"proxy"}]}`,
		`{"outbounds":[{"type":"vless","tag":"s","server":["a"],"server_port":"x"}]}`,
		`{"outbounds":[{"type":"vless","tag":"s","server":"a.example.net","server_port":1,"uuid":5,"tls":"x"}]}`,
		`{"outbounds":[{"type":7}]}`,
	} {
		list, err := ParseList(context.Background(), []byte(body), realCodec)
		if err == nil {
			for _, server := range list.Servers {
				require.NotEmpty(t, server.Name, body)
			}
		}
	}
}

// boundShapes are small versions of the shapes that once took time or memory out of proportion to
// their size (TestBoundsTime, TestBoundsAmplification), for the fuzzers to start from.
func boundShapes() []string {
	var keys, headers, outbounds, prefixes strings.Builder
	for index := 0; index < 2000; index++ {
		keys.WriteString(`,"k` + strconv.Itoa(index) + `":0`)
		if index > 0 {
			headers.WriteString(",")
			prefixes.WriteString(",")
		}
		headers.WriteString(`"h` + strconv.Itoa(index) + `":"v"`)
		prefixes.WriteString(`"b"`)
		outbounds.WriteString(`{"protocol":"vless","tag":"s` + strconv.Itoa(index) + `","settings":{"address":"a.example.net","port":1,"id":"x"},"streamSettings":{"sockopt":{"dialerProxy":"f"}}},`)
	}
	vless := `{"tag":"proxy","protocol":"vless","settings":{"address":"a.example.net","port":443,"id":"c0ffee00-0000-4000-8000-000000000043"}`
	return []string{
		"[" + xrayConfigOf("R", vless+keys.String()+"}") + "]",
		"[" + xrayConfigOf("R", vless+`,"streamSettings":{"network":"ws","wsSettings":{"headers":{`+headers.String()+`}}}}`) + "]",
		"[" + xrayConfigOf("R", vless+`,"streamSettings":{"network":"xhttp","xhttpSettings":{"path":"/"`+keys.String()+`}}}`) + "]",
		`{"remarks":"` + strings.Repeat("R", 4096) + `","outbounds":[` + outbounds.String() + `{"protocol":"freedom","tag":"f","settings":{"fragment":{"packets":"tlshello","length":"100-200"}}}],"routing":{"balancers":[{"selector":[` + prefixes.String() + `]}]}}`,
		`{"outbounds":[{"type":"vless","tag":"s","server":"a.example.net","server_port":443,"uuid":"c0ffee00-0000-4000-8000-000000000043","transport":{"type":"ws","headers":{` + headers.String() + `}}}]}`,
	}
}

// fuzzRead reads a body as the backend does, within a deadline: it must stop at the deadline (the
// end of a download), and what it makes stays within the budget of the body.
func fuzzRead(t *testing.T, content []byte) List {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	started := time.Now()
	list, _ := ParseList(ctx, content, realCodec)
	if took := time.Since(started); took > 6*time.Second {
		t.Fatalf("the reading went on %v past its deadline", took-3*time.Second)
	}
	if len(content) > 0 && made(list) > 4*len(content)+256<<10 {
		t.Fatalf("the servers take %d bytes of a body of %d", made(list), len(content))
	}
	for _, server := range list.Servers {
		if server.Name == "" || (server.Reason == "" && server.ID == "") {
			t.Fatalf("a server without a name, or usable without an ID")
		}
	}
	return list
}

// The readers never panic on what a provider may send, end at the deadline of the download, and
// every server they make has a name and either a reason or a link the decoder took.
func FuzzReadXray(f *testing.F) {
	seeds, _ := filepath.Glob("testdata/xray/*.json")
	more, _ := filepath.Glob("testdata/remnawave/*/xray.json")
	for _, file := range append(seeds, more...) {
		if content, err := os.ReadFile(file); err == nil {
			f.Add(content)
		}
	}
	for _, shape := range boundShapes()[:4] {
		f.Add([]byte(shape))
	}
	f.Fuzz(func(t *testing.T, content []byte) {
		fuzzRead(t, content)
	})
}

func FuzzReadSingBox(f *testing.F) {
	seeds, _ := filepath.Glob("testdata/singbox/*.json")
	more, _ := filepath.Glob("testdata/remnawave/*/singbox.json")
	for _, file := range append(seeds, more...) {
		if content, err := os.ReadFile(file); err == nil {
			f.Add(content)
		}
	}
	f.Add([]byte(boundShapes()[4]))
	f.Fuzz(func(t *testing.T, content []byte) {
		fuzzRead(t, content)
		servers, _ := readSingBox(nil, objectOf(content), realCodec)
		for _, server := range servers {
			if server.Name == "" || (server.Reason == "" && server.ID == "") {
				t.Fatalf("a server without a name, or usable without an ID")
			}
		}
	})
}

// The seeds of the shapes are read within their bounds.
func TestBoundShapes(t *testing.T) {
	t.Parallel()
	for _, shape := range boundShapes() {
		fuzzRead(t, []byte(shape))
	}
}

// xrayProbe is a server outbound of the probes of the review: VLESS over TLS.
func xrayProbe(tag string, host string) string {
	return `{"tag":"` + tag + `","protocol":"vless","settings":{"address":"` + host + `","port":443,"id":"c0ffee00-0000-4000-8000-000000000001","encryption":"none"},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"` + host + `"}}}`
}

// serversOf reads a body and gives its servers.
func serversOf(t *testing.T, body string) []Server {
	t.Helper()
	list, err := ParseList(context.Background(), []byte(body), realCodec)
	require.NoError(t, err, body)
	return list.Servers
}

// The servers of a configuration are those Xray uses: the default outbound (the first, unless a
// rule takes all traffic), the targets of the rules, the members of the balancers. The default
// one is the main server of its configuration unless a balancer chooses it among others.
func TestXrayDefaultOutbound(t *testing.T) {
	t.Parallel()
	servers := serversOf(t, `[{"remarks":"Main","outbounds":[`+xrayProbe("main", "a.example.net")+`,`+xrayProbe("streaming", "b.example.net")+`,{"tag":"direct","protocol":"freedom"}],
		"routing":{"rules":[{"type":"field","domain":["geosite:netflix"],"outboundTag":"streaming"},{"type":"field","ip":["geoip:private"],"outboundTag":"direct"}]}}]`)
	require.Len(t, servers, 2, "the default outbound and the target of a rule")
	require.Equal(t, "Main", servers[0].Name)
	require.Contains(t, servers[0].Link, "@a.example.net:443")
	require.Contains(t, servers[1].Link, "@b.example.net:443")
	// a relay that is the default outbound is what Xray uses; the exit it relays nothing reaches
	servers = serversOf(t, `[{"remarks":"D","outbounds":[`+xrayProbe("entry", "relay.example.net")+`,{"tag":"exit","protocol":"vless","settings":{"address":"exit.example.net","port":443,"id":"c0ffee00-0000-4000-8000-000000000002","encryption":"none"},"streamSettings":{"security":"tls","sockopt":{"dialerProxy":"entry"}}}]}]`)
	require.Len(t, servers, 1)
	require.Contains(t, servers[0].Link, "@relay.example.net:443")
	require.Equal(t, "D", servers[0].Name)
	// a rule that takes all traffic to a balancer: the default outbound is used by none
	servers = serversOf(t, `[{"remarks":"B","outbounds":[`+xrayProbe("first", "a.example.net")+`,`+xrayProbe("x-1", "b.example.net")+`,`+xrayProbe("x-2", "c.example.net")+`],
		"routing":{"balancers":[{"tag":"b","selector":["x-"]}],"rules":[{"type":"field","network":"tcp,udp","balancerTag":"b"}]}}]`)
	require.Len(t, servers, 2)
	for _, rule := range []string{`{"network":"tcp,udp","balancerTag":"b"}`, `{"port":"0-65535","balancerTag":"b"}`, `{"network":["udp","tcp"],"port":"1-65535","balancerTag":"b"}`} {
		require.True(t, takesAll(objectOf(json.RawMessage(rule))), rule)
	}
	for _, rule := range []string{`{"network":"tcp","balancerTag":"b"}`, `{"port":"443","balancerTag":"b"}`, `{"outboundTag":"b"}`, `{"network":"tcp,udp","domain":["x"],"balancerTag":"b"}`} {
		require.False(t, takesAll(objectOf(json.RawMessage(rule))), rule)
	}
}

// The speeds of Brutal as Xray reads them: bits a second, with units and decimals, made megabits
// a second; the speed down goes to the server whatever the congestion control.
func TestXrayBrutalSpeeds(t *testing.T) {
	t.Parallel()
	hysteria := func(quic string) Server {
		return serversOf(t, `[{"remarks":"B","outbounds":[{"tag":"proxy","protocol":"hysteria","settings":{"version":2,"address":"h.example.net","port":443},"streamSettings":{"network":"hysteria","security":"tls","tlsSettings":{"serverName":"h.example.net"},"hysteriaSettings":{"version":2,"auth":"secret-auth"},"finalmask":{"quicParams":`+quic+`}}}]}]`)[0]
	}
	for quic, want := range map[string][2]any{
		`{"congestion":"brutal","brutalUp":"1 gbps","brutalDown":"2 gbps"}`:  {float64(1000), float64(2000)},
		`{"brutalUp":"100000000","brutalDown":"200000000"}`:                  {float64(100), float64(200)},
		`{"brutalUp":"50 mbps","brutalDown":"12500 kbps"}`:                   {float64(50), float64(13)},
		`{"congestion":"bbr","brutalUp":"100 mbps","brutalDown":"200 mbps"}`: {nil, float64(200)},
		`{"congestion":"reno","brutalDown":200000000}`:                       {nil, float64(200)},
	} {
		server := hysteria(quic)
		require.True(t, server.Usable(), "%s: %s", quic, server.Reason)
		require.Equal(t, want[0], outboundAt(t, server, "up_mbps"), quic)
		require.Equal(t, want[1], outboundAt(t, server, "down_mbps"), quic)
	}
	rounded := hysteria(`{"brutalUp":"50.5 mbps"}`)
	require.Equal(t, float64(51), outboundAt(t, rounded, "up_mbps"))
	require.Contains(t, rounded.Notes, "the speeds of Brutal are rounded to whole megabits a second")
	unread := hysteria(`{"brutalUp":"fast"}`)
	require.Nil(t, outboundAt(t, unread, "up_mbps"))
	require.Contains(t, unread.Notes, "the speeds of Brutal cannot be read and are not used")
	for text, want := range map[string]float64{`"1 gbps"`: 1000, `"8 kbps"`: 0.008, `100`: 0.0001, `"2.5m"`: 2.5, `"1t"`: 1e6} {
		megabits, read := xrayBandwidth(json.RawMessage(text))
		require.True(t, read, text)
		require.InDelta(t, want, megabits, 1e-9, text)
	}
	for _, text := range []string{`"1 xbps"`, `"-5 mbps"`, `"1e400"`, `"9999999 tbps"`} {
		_, read := xrayBandwidth(json.RawMessage(text))
		require.False(t, read, text)
	}
}

// The method of the stream names the network of Hysteria as it does of the others.
func TestXrayHysteriaMethod(t *testing.T) {
	t.Parallel()
	server := serversOf(t, `[{"remarks":"H","outbounds":[{"tag":"proxy","protocol":"hysteria","settings":{"version":2,"address":"h.example.net","port":443},"streamSettings":{"method":"hysteria","network":"tcp","security":"tls","tlsSettings":{"serverName":"h.example.net"},"hysteriaSettings":{"version":2,"auth":"secret-auth"}}}]}]`)[0]
	require.True(t, server.Usable(), server.Reason)
	require.Equal(t, "hysteria2", outboundAt(t, server, "type"))
	require.Empty(t, server.Notes)
}

// direct and block are Xray's names of freedom and blackhole: no servers; a direct dialer with a
// fragment is the older form of the cut of the hello, and a dialer's own finalmask its newer form.
func TestXrayFreedomForms(t *testing.T) {
	t.Parallel()
	servers := serversOf(t, `[{"remarks":"R","outbounds":[`+xrayProbe("proxy", "a.example.net")+`,{"tag":"direct","protocol":"direct"},{"tag":"block","protocol":"block"}],"routing":{"rules":[{"type":"field","ip":["geoip:private"],"outboundTag":"direct"},{"type":"field","protocol":["bittorrent"],"outboundTag":"block"}]}}]`)
	require.Len(t, servers, 1)
	servers = serversOf(t, `[{"remarks":"R","outbounds":[`+xrayProbe("main", "a.example.net")+`,{"tag":"direct","protocol":"direct"}]}]`)
	require.Len(t, servers, 1)
	dialed := func(dialer string) Server {
		return serversOf(t, `[{"remarks":"F","outbounds":[{"tag":"proxy","protocol":"vless","settings":{"address":"a.example.net","port":443,"id":"c0ffee00-0000-4000-8000-000000000001","encryption":"none"},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"a.example.net"},"sockopt":{"dialerProxy":"frag"}}},`+dialer+`]}]`)[0]
	}
	for _, dialer := range []string{
		`{"tag":"frag","protocol":"direct","settings":{"fragment":{"packets":"tlshello","length":"100-200","interval":"0"}}}`,
		`{"tag":"frag","protocol":"freedom","streamSettings":{"finalmask":{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","length":"100-200"}}]}}}`,
	} {
		server := dialed(dialer)
		require.True(t, server.Usable(), server.Reason)
		require.Empty(t, server.Notes, dialer)
		mask := outboundAt(t, server, "finalmask").(map[string]any)["tcp"].([]any)[0].(map[string]any)
		require.Equal(t, "tlshello", mask["packets"], dialer)
		require.Equal(t, "100-200", mask["length"], dialer)
	}
	large := dialed(`{"tag":"frag","protocol":"freedom","streamSettings":{"finalmask":{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","length":"` + strings.Repeat("1", 5000) + `"}}]}}}`)
	require.Equal(t, "the masks of the provider's dialer are too large to be taken", large.Reason)
}

// An HTTPS proxy of Xray says Chrome's hello when it names none, as the others do.
func TestXrayHTTPSFingerprint(t *testing.T) {
	t.Parallel()
	server := serversOf(t, `[{"remarks":"P","outbounds":[{"tag":"proxy","protocol":"http","settings":{"address":"px.example.net","port":8443},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"px.example.net"}}}]}]`)[0]
	require.True(t, server.Usable(), server.Reason)
	require.Equal(t, "chrome", outboundAt(t, server, "tls.utls.fingerprint"))
	require.Equal(t, "chrome", paramsOf(t, server.Link).Get("fp"))
}

// A header whose value a link cannot carry (another link and a space: a bot's User-Agent) is left
// out with a note, and the server stays; one name in two cases is one header.
func TestXrayHeadersALinkCannotCarry(t *testing.T) {
	t.Parallel()
	server := serversOf(t, `[{"remarks":"U","outbounds":[{"tag":"proxy","protocol":"vless","settings":{"address":"w.example.net","port":443,"id":"c0ffee00-0000-4000-8000-000000000001","encryption":"none"},"streamSettings":{"network":"ws","security":"tls","tlsSettings":{"serverName":"w.example.net"},"wsSettings":{"path":"/ws","headers":{"User-Agent":"Mozilla/5.0 (compatible; +http://example.com/bot)","X-Kept":"1","x-kept":"2"}}}}]}]`)[0]
	require.True(t, server.Usable(), server.Reason)
	require.Contains(t, server.Notes, "the header User-Agent is left out: a link cannot carry its value")
	require.Contains(t, server.Notes, "the header x-kept is given twice in other cases: one is sent")
	require.Equal(t, "1", outboundAt(t, server, "transport.headers.X-Kept"))
	require.Nil(t, outboundAt(t, server, "transport.headers.User-Agent"))
}

// Xray's other names of the methods of Shadowsocks are the methods.
func TestXrayShadowsocksAliases(t *testing.T) {
	t.Parallel()
	for alias, method := range map[string]string{"aead_aes_128_gcm": "aes-128-gcm", "AEAD_AES_256_GCM": "aes-256-gcm", "AEAD_CHACHA20_POLY1305": "chacha20-ietf-poly1305", "aead_xchacha20_poly1305": "xchacha20-ietf-poly1305"} {
		server := serversOf(t, `[{"remarks":"S","outbounds":[{"tag":"proxy","protocol":"shadowsocks","settings":{"address":"ss.example.net","port":8388,"method":"`+alias+`","password":"fixture-pass"}}]}]`)[0]
		require.True(t, server.Usable(), "%s: %s", alias, server.Reason)
		require.Equal(t, method, outboundAt(t, server, "method"), alias)
	}
}

// The provider's certificate authority replaces the system's roots in sing-box, where Xray adds
// it to them: so noted, unless the configuration has the system's roots off too.
func TestXrayCertificateRoots(t *testing.T) {
	t.Parallel()
	certificate := `"certificates":[{"usage":"verify","certificate":["-----BEGIN CERTIFICATE-----","MIIB","-----END CERTIFICATE-----"]}]`
	added := readOne(t, `{"tag":"proxy","protocol":"vless","settings":{"address":"c.example.net","port":443,"id":"c0ffee00-0000-4000-8000-000000000044"},"streamSettings":{"security":"tls","tlsSettings":{`+certificate+`}}}`)
	require.Equal(t, []string{"the server's certificate is verified by the provider's certificate authority instead of the system's roots"}, added.Notes)
	alone := readOne(t, `{"tag":"proxy","protocol":"vless","settings":{"address":"c.example.net","port":443,"id":"c0ffee00-0000-4000-8000-000000000044"},"streamSettings":{"security":"tls","tlsSettings":{`+certificate+`,"disableSystemRoot":true}}}`)
	require.Empty(t, alone.Notes)
}

// Servers podkop made no link of are told apart by their names and reasons: another refusal is
// another list.
func TestSameServersWithoutLinks(t *testing.T) {
	t.Parallel()
	first := serversOf(t, `[{"remarks":"W","outbounds":[{"tag":"proxy","protocol":"wireguard","settings":{}}]},{"remarks":"ok","outbounds":[`+xrayProbe("proxy", "a.example.net")+`]}]`)
	second := serversOf(t, `[{"remarks":"W","outbounds":[{"tag":"proxy","protocol":"masque","settings":{}}]},{"remarks":"ok","outbounds":[`+xrayProbe("proxy", "a.example.net")+`]}]`)
	require.Empty(t, first[0].Link)
	require.NotEqual(t, first[0].Reason, second[0].Reason)
	require.False(t, SameServers(first, second))
	require.False(t, SameList(first, second))
	require.True(t, SameServers(first, serversOf(t, `[{"remarks":"W","outbounds":[{"tag":"proxy","protocol":"wireguard","settings":{}}]},{"remarks":"ok","outbounds":[`+xrayProbe("proxy", "a.example.net")+`]}]`)))
}

// Extra settings of XHTTP that are not an object: Xray refuses the configuration, the server gets
// that reason.
func TestXrayExtraNotAnObject(t *testing.T) {
	t.Parallel()
	server := readOne(t, `{"tag":"proxy","protocol":"vless","settings":{"address":"x.example.net","port":443,"id":"c0ffee00-0000-4000-8000-000000000001","encryption":"none"},"streamSettings":{"network":"xhttp","security":"tls","tlsSettings":{"serverName":"x.example.net"},"xhttpSettings":{"path":"/x","extra":"{\"downloadSettings\":{}}"}}}`)
	require.Equal(t, "the extra settings of XHTTP are not an object", server.Reason)
}

// The size of the segments and of the window of TCP change what goes over the wire: noted.
func TestXraySockoptOnTheWire(t *testing.T) {
	t.Parallel()
	server := readOne(t, `{"tag":"proxy","protocol":"vless","settings":{"address":"s.example.net","port":443,"id":"c0ffee00-0000-4000-8000-000000000045"},"streamSettings":{"sockopt":{"tcpMaxSeg":500,"tcpWindowClamp":600,"mark":1}}}`)
	require.Equal(t, []string{"streamSettings.sockopt.tcpMaxSeg is a setting of the provider's app and is left out", "streamSettings.sockopt.tcpWindowClamp is a setting of the provider's app and is left out"}, server.Notes)
}
