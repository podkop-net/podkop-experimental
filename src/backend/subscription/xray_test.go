package subscription

import (
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
	list, err := ParseList([]byte("["+xrayConfigOf("R", outbound)+"]"), realCodec)
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
		list, err := ParseList([]byte(body), realCodec)
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
	_, err := ParseList([]byte(`{"secret-key":"VALUE-1234"}`), realCodec)
	require.Equal(t, "the provider sent JSON that is not a configuration of Xray or sing-box", err.Error())
	_, err = ParseList([]byte("proxies:\n  - name: SECRET\n"), realCodec)
	require.Equal(t, "clash", err.(*Failure).Code)
	require.NotContains(t, err.Error(), "SECRET")
	require.Contains(t, err.Error(), "which podkop does not read")
}

// A list of links Happ alone reads (happ://crypt…) is refused with a code of its own; beside a
// real link it is skipped as before.
func TestHappCrypt(t *testing.T) {
	t.Parallel()
	_, err := ParseList([]byte("happ://crypt3/SECRETDATA\nhapp://crypt4/MORE\n"), Codec{Decode: fakeDecode})
	require.Equal(t, "happ-crypt", err.(*Failure).Code)
	require.NotContains(t, err.Error(), "SECRETDATA")
	encoded := base64.StdEncoding.EncodeToString([]byte("happ://crypt/x\n"))
	_, err = ParseList([]byte(encoded), Codec{Decode: fakeDecode})
	require.Equal(t, "happ-crypt", err.(*Failure).Code)
	list, err := ParseList([]byte("happ://crypt3/x\nvless://u@a.example:443#A\n"), Codec{Decode: fakeDecode})
	require.NoError(t, err)
	require.Len(t, list.Servers, 1)
	_, err = ParseList([]byte("happ://routing/onadd/x\n"), Codec{Decode: fakeDecode})
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
		list, err := ParseList([]byte(body), realCodec)
		require.NoError(t, err, body)
		var found []string
		for _, server := range list.Servers {
			found = append(found, server.Name)
		}
		return found
	}
	// balancer members by prefix, the fallback, a rule's target; not the other outbound
	require.Equal(t, []string{"R", "eu-1", "eu-2", "backup", "routed"}, names(`{"remarks":"R","outbounds":[`+server("proxy", "p.example.net")+`,`+server("eu-1", "a.example.net")+`,`+
		server("eu-2", "b.example.net")+`,`+server("backup", "c.example.net")+`,`+server("routed", "d.example.net")+`,`+server("other", "e.example.net")+`],
		"routing":{"balancers":[{"tag":"b","selector":["eu-"],"fallbackTag":"backup"}],"rules":[{"outboundTag":"routed"},{"outboundTag":"direct"}]}}`))
	// none of these: every server but a relay of another
	require.Equal(t, []string{"first", "second"}, names(`{"remarks":"R","outbounds":[`+relayed("first", "a.example.net", "relay")+`,`+server("second", "b.example.net")+`,`+server("relay", "r.example.net")+`]}`))
	// its only server takes the remarks
	require.Equal(t, []string{"R"}, names(`{"remarks":"R","outbounds":[`+relayed("first", "a.example.net", "relay")+`,`+server("relay", "r.example.net")+`]}`))
	// the tags Remnawave numbers are no names; no remarks: the tag; neither: the number
	require.Equal(t, []string{"R", "R"}, names(`{"remarks":"R","outbounds":[`+server("proxy", "a.example.net")+`,`+server("proxy-2", "b.example.net")+`],"routing":{"balancers":[{"selector":["proxy"]}]}}`))
	require.Equal(t, []string{"server 1"}, names(`{"outbounds":[`+server("", "a.example.net")+`]}`))
	require.Equal(t, []string{"proxy"}, names(`{"outbounds":[`+server("proxy", "a.example.net")+`]}`))
	// the same server in two configurations under one name: once; under two names: twice
	one := `{"remarks":"Same","outbounds":[` + server("proxy", "a.example.net") + `]}`
	other := `{"remarks":"Other","outbounds":[` + server("proxy", "a.example.net") + `]}`
	require.Equal(t, []string{"Same"}, names("["+one+","+one+"]"))
	require.Equal(t, []string{"Same", "Other"}, names("["+one+","+other+"]"))
	// a member that is the proxy of another configuration takes the name of that one
	withExit := `{"remarks":"A","outbounds":[` + server("proxy", "a.example.net") + `,` + server("exit", "b.example.net") + `],"routing":{"balancers":[{"selector":["proxy","exit"]}]}}`
	exit := `{"remarks":"B","outbounds":[` + server("proxy", "b.example.net") + `]}`
	require.Equal(t, []string{"A", "B"}, names("["+withExit+","+exit+"]"))
}

// The chains of the provider are notes: the server is connected directly.
func TestXrayChainNotes(t *testing.T) {
	t.Parallel()
	list, err := ParseList([]byte(`{"remarks":"Exit","outbounds":[
		{"tag":"proxy","protocol":"vless","settings":{"address":"e.example.net","port":443,"id":"c0ffee00-0000-4000-8000-000000000007"},"streamSettings":{"sockopt":{"dialerProxy":"🔒 Relay"}}},
		{"tag":"🔒 Relay","protocol":"vless","settings":{"address":"r.example.net","port":443,"id":"c0ffee00-0000-4000-8000-000000000008"}}]}`), realCodec)
	require.NoError(t, err)
	require.Len(t, list.Servers, 1)
	require.Equal(t, []string{"the provider connects it through 🔒 Relay; podkop connects it directly"}, list.Servers[0].Notes)
	require.Nil(t, outboundAt(t, list.Servers[0], "detour"))
	// the older form of the cut of the hello: a freedom dialer with a fragment
	list, err = ParseList([]byte(`{"remarks":"F","outbounds":[
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
		list, err := ParseList(body, realCodec)
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
	list, err := ParseList([]byte(body), realCodec)
	require.NoError(t, err)
	require.Equal(t, len(configs), list.Configs)
	require.Len(t, list.Servers, len(configs))
	require.Less(t, time.Since(started), 60*time.Second)

	deep := strings.Repeat(`{"outbounds":[`, 1000) + strings.Repeat(`]}`, 1000)
	_, err = ParseList([]byte(deep), realCodec)
	require.Error(t, err)
	deeper := strings.Repeat("[", 20000) + strings.Repeat("]", 20000)
	_, err = ParseList([]byte(deeper), realCodec)
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
		list, err := ParseList([]byte(body), realCodec)
		if err == nil {
			for _, server := range list.Servers {
				require.NotEmpty(t, server.Name, body)
			}
		}
	}
}

// The readers never panic on what a provider may send, and every server they make has a name and
// either a reason or a link the decoder took.
func FuzzReadXray(f *testing.F) {
	seeds, _ := filepath.Glob("testdata/xray/*.json")
	more, _ := filepath.Glob("testdata/remnawave/*/xray.json")
	for _, file := range append(seeds, more...) {
		if content, err := os.ReadFile(file); err == nil {
			f.Add(content)
		}
	}
	f.Fuzz(func(t *testing.T, content []byte) {
		list, _ := ParseList(content, realCodec)
		for _, server := range list.Servers {
			if server.Name == "" || (server.Reason == "" && server.ID == "") {
				t.Fatalf("a server without a name, or usable without an ID")
			}
		}
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
	f.Fuzz(func(t *testing.T, content []byte) {
		servers, _ := readSingBox(objectOf(content), realCodec)
		for _, server := range servers {
			if server.Name == "" || (server.Reason == "" && server.ID == "") {
				t.Fatalf("a server without a name, or usable without an ID")
			}
		}
	})
}
