package subscription

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/common/sharelink"
	"github.com/sagernet/sing-box/option"
	sjson "github.com/sagernet/sing/common/json"
	"github.com/stretchr/testify/require"
)

// optionLeaves lists every option of a structure of options by its path, as the decoder's policy
// walks them (common/sharelink fallback_test.go): the members of a union and the embedded
// structures, down to a type that reads itself; a denied option is one leaf. denied tells the
// options singBoxDenied leaves out, with the tags the decoder denies besides (a reference to
// another object, an option left out of the schema).
func optionLeaves(valueType reflect.Type, path string, denied bool, leaves map[string]bool, depth int) {
	for valueType.Kind() == reflect.Pointer {
		valueType = valueType.Elem()
	}
	pointer := reflect.PointerTo(valueType)
	readsItself := pointer.Implements(reflect.TypeOf((*interface{ UnmarshalJSON([]byte) error })(nil)).Elem()) ||
		pointer.Implements(reflect.TypeOf((*sjson.ContextUnmarshaler)(nil)).Elem())
	fields := map[string][]reflect.StructField{}
	var collect func(structure reflect.Type)
	collect = func(structure reflect.Type) {
		for index := 0; index < structure.NumField(); index++ {
			field := structure.Field(index)
			if !field.IsExported() {
				continue
			}
			fieldType := field.Type
			if fieldType.Kind() == reflect.Pointer {
				fieldType = fieldType.Elem()
			}
			tag, hasTag := field.Tag.Lookup("json")
			name, _, _ := strings.Cut(tag, ",")
			switch {
			case name == "-":
				if fieldType.Kind() == reflect.Struct {
					collect(fieldType)
				}
			case field.Anonymous && (!hasTag || name == "") && fieldType.Kind() == reflect.Struct:
				collect(fieldType)
			case name != "":
				fields[name] = append(fields[name], field)
			}
		}
	}
	if valueType.Kind() == reflect.Struct {
		collect(valueType)
	}
	if denied || valueType.Kind() != reflect.Struct || depth > 8 || (path != "" && readsItself && len(fields) == 0) || len(fields) == 0 {
		leaves[path] = denied
		return
	}
	for name, candidates := range fields {
		for _, field := range candidates {
			_, reference := field.Tag.Lookup("reference")
			deny := singBoxDeniedName(name) || reference || field.Tag.Get("schema") == "omit"
			if path == "" && (name == "server" || name == "server_port") {
				// what the link says itself: the decoder denies them as a path, the readers write
				// them as the server
				deny = true
			}
			optionLeaves(field.Type, strings.TrimPrefix(path+"."+name, "."), deny, leaves, depth+1)
		}
	}
}

// engineOptions is the decoder's own list of every option of every outbound a link makes, in the
// engine this backend is built with (common/sharelink testdata/options-1.14.txt of the module of
// sing-box, as go list finds it in the module cache).
func engineOptions(t *testing.T) string {
	t.Helper()
	output, err := exec.Command("go", "list", "-m", "-json", "github.com/sagernet/sing-box").Output()
	require.NoError(t, err, "go list of the engine's module")
	var module struct {
		Dir     string
		Replace *struct{ Dir string }
	}
	require.NoError(t, json.Unmarshal(output, &module))
	directory := module.Dir
	if module.Replace != nil && module.Replace.Dir != "" {
		directory = module.Replace.Dir
	}
	require.NotEmpty(t, directory, "the engine's module is in the module cache")
	return filepath.Join(directory, "common", "sharelink", "testdata", "options-1.14.txt")
}

// The options the sing-box reader leaves out are those the decoder denies: the decoder's list of
// every option of every outbound a link makes, read from the engine this backend is built with,
// has the same options, and the same ones denied, as this sing-box's option types walked with
// singBoxDenied. An option the engine adds, or a name it denies, fails this until both are looked
// at.
func TestSingBoxDeniedAgreesWithTheDecoder(t *testing.T) {
	t.Parallel()
	file, err := os.Open(engineOptions(t))
	require.NoError(t, err)
	defer file.Close()
	decoder := map[string]bool{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.SplitN(scanner.Text(), " ", 3)
		require.Len(t, fields, 3)
		decoder[fields[0]+" "+fields[1]] = strings.HasPrefix(fields[2], "denied")
	}
	require.NoError(t, scanner.Err())
	ours := map[string]bool{}
	types := map[string]any{
		"vless": option.VLESSOutboundOptions{}, "vmess": option.VMessOutboundOptions{}, "trojan": option.TrojanOutboundOptions{},
		"shadowsocks": option.ShadowsocksOutboundOptions{}, "socks": option.SOCKSOutboundOptions{}, "http": option.HTTPOutboundOptions{},
		"hysteria": option.HysteriaOutboundOptions{}, "hysteria2": option.Hysteria2OutboundOptions{}, "tuic": option.TUICOutboundOptions{},
		"anytls": option.AnyTLSOutboundOptions{}, "naive": option.NaiveOutboundOptions{},
	}
	require.Len(t, singBoxTypes, len(types))
	for kind, options := range types {
		require.True(t, singBoxTypes[kind], kind)
		leaves := map[string]bool{}
		optionLeaves(reflect.TypeOf(options), "", false, leaves, 0)
		for path, denied := range leaves {
			ours[kind+" "+path] = denied
		}
	}
	var missing, extra, disagree []string
	for key, denied := range decoder {
		if mine, found := ours[key]; !found {
			missing = append(missing, key)
		} else if mine != denied {
			disagree = append(disagree, key)
		}
	}
	for key := range ours {
		if _, found := decoder[key]; !found {
			extra = append(extra, key)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	sort.Strings(disagree)
	require.Empty(t, missing, "options of the decoder's list this sing-box does not have")
	require.Empty(t, extra, "options of this sing-box the decoder's list does not have")
	require.Empty(t, disagree, "options the reader and the decoder do not deny alike")
	// the list is the decoder's: what it denies, it refuses in a link
	for _, path := range []string{"detour", "bind_interface", "routing_mark", "domain_resolver", "domain_strategy", "tls.certificate_path", "tls.handshake_timeout", "realm.server_url"} {
		_, _, err := sharelink.Decode("hysteria2://p@example.org:443?sb." + path + "=x")
		var refusal *sharelink.Refusal
		require.True(t, errors.As(err, &refusal), path)
		require.Equal(t, "sb-denied", refusal.ID, path)
	}
}

// readSingBoxBody reads a sing-box configuration and gives its servers by name.
func readSingBoxBody(t *testing.T, body string) map[string]Server {
	t.Helper()
	list, err := ParseList(context.Background(), []byte(body), realCodec)
	require.NoError(t, err, body)
	require.Equal(t, FormatSingBox, list.Format)
	servers := map[string]Server{}
	for _, server := range list.Servers {
		servers[server.Name] = server
	}
	return servers
}

// A server of a sing-box configuration is the server of the provider's link: the options at
// sing-box's defaults that panels write (packet_encoding xudp, a multiplex switched off, the ALPN
// of the transport) are those the link does not carry.
func TestSingBoxIDsOfTheLinks(t *testing.T) {
	t.Parallel()
	const uuid = "c0ffee00-0000-4000-8000-000000000020"
	const key = "jYM97hnBoGvH3Wyf0ExRqCn75nTpzcUVIVb0_q18RvY"
	servers := readSingBoxBody(t, `{"outbounds":[
		{"type":"vless","tag":"reality","server":"r.example.net","server_port":443,"uuid":"`+uuid+`","flow":"xtls-rprx-vision","packet_encoding":"xudp",
		 "tls":{"enabled":true,"server_name":"www.example.com","utls":{"enabled":true,"fingerprint":"chrome"},"reality":{"enabled":true,"public_key":"`+key+`","short_id":"0123"}},
		 "multiplex":{"enabled":false,"protocol":"smux","max_streams":32}},
		{"type":"trojan","tag":"ws","server":"t.example.net","server_port":443,"password":"p-1","tls":{"enabled":true,"server_name":"t.example.net","alpn":["http/1.1"],"utls":{"enabled":true,"fingerprint":"chrome"}},
		 "transport":{"type":"ws","path":"/w","headers":{"Host":"t.example.net"}}},
		{"type":"trojan","tag":"grpc","server":"g.example.net","server_port":443,"password":"p-2","tls":{"enabled":true,"server_name":"g.example.net","alpn":"h2","utls":{"enabled":true,"fingerprint":"chrome"}},
		 "transport":{"type":"grpc","service_name":"s"}},
		{"type":"hysteria2","tag":"hy2","server":"h.example.net","server_port":443,"password":"a-1","obfs":{"type":"salamander","password":"o-1"},"tls":{"enabled":true,"server_name":"h.example.net","alpn":["h3"]}},
		{"type":"vless","tag":"alpn","server":"a.example.net","server_port":443,"uuid":"`+uuid+`","tls":{"enabled":true,"server_name":"a.example.net","alpn":["h2"],"utls":{"enabled":true,"fingerprint":"chrome"}}},
		{"type":"vless","tag":"h2","server":"h2.example.net","server_port":443,"uuid":"`+uuid+`","tls":{"enabled":true,"server_name":"h2.example.net","alpn":["h2"],"utls":{"enabled":true,"fingerprint":"chrome"}},
		 "transport":{"type":"http","host":["h2.example.net"],"path":"/h2"}},
		{"type":"selector","tag":"proxy","outbounds":["reality","ws","grpc","hy2","alpn","h2"]},{"type":"direct","tag":"direct"}]}`)
	for name, link := range map[string]string{
		"reality": "vless://" + uuid + "@r.example.net:443?encryption=none&flow=xtls-rprx-vision&type=tcp&security=reality&sni=www.example.com&fp=chrome&pbk=" + key + "&sid=0123#x",
		"ws":      "trojan://p-1@t.example.net:443?type=ws&path=%2Fw&host=t.example.net&security=tls&sni=t.example.net&fp=chrome&alpn=http%2F1.1#x",
		"grpc":    "trojan://p-2@g.example.net:443?type=grpc&serviceName=s&mode=gun&security=tls&sni=g.example.net&fp=chrome&alpn=h2#x",
		"hy2":     "hysteria2://a-1@h.example.net:443/?obfs=salamander&obfs-password=o-1&sni=h.example.net#x",
		"alpn":    "vless://" + uuid + "@a.example.net:443?encryption=none&type=tcp&security=tls&sni=a.example.net&fp=chrome&alpn=h2#x",
		// Marzban's h2 host: sing-box's http transport asks for h2 itself, the decoder drops alpn=h2
		"h2": "vless://" + uuid + "@h2.example.net:443?encryption=none&type=http&host=h2.example.net&path=%2Fh2&security=tls&sni=h2.example.net&fp=chrome&alpn=h2#x",
	} {
		server, found := servers[name]
		require.True(t, found, name)
		require.True(t, server.Usable(), "%s: %s", name, server.Reason)
		require.Empty(t, server.Notes, name)
		fromLink := parseLink(link, 1, realDecode)
		require.Equal(t, string(fromLink.outbound), string(server.outbound), name)
		require.Equal(t, fromLink.ID, server.ID, name)
	}
	// the control: another short id is another server
	other := readSingBoxBody(t, `{"outbounds":[{"type":"vless","tag":"reality","server":"r.example.net","server_port":443,"uuid":"`+uuid+`","flow":"xtls-rprx-vision",
		"tls":{"enabled":true,"server_name":"www.example.com","utls":{"enabled":true,"fingerprint":"chrome"},"reality":{"enabled":true,"public_key":"`+key+`","short_id":"4567"}}}]}`)
	require.NotEqual(t, servers["reality"].ID, other["reality"].ID)
}

// The options a link does not set are left out of a sing-box outbound, each with a note that
// names it without its value; the outbound has none of them.
func TestSingBoxPolicy(t *testing.T) {
	t.Parallel()
	servers := readSingBoxBody(t, `{"outbounds":[{"type":"trojan","tag":"T","server":"t.example.net","server_port":443,"password":"SECRET-PASSWORD",
		"detour":"relay","bind_interface":"wan-SECRET","routing_mark":4321,"domain_resolver":{"server":"local-SECRET"},"domain_strategy":"ipv4_only","fallback_delay":"300ms",
		"tls":{"enabled":true,"server_name":"t.example.net","certificate_path":"/etc/SECRET.pem","handshake_timeout":"1h"},
		"transport":{"type":"ws","path":"/w","headers":{"routing_mark":"a header, not an option"}}},
		{"type":"vless","tag":"relay","server":"r.example.net","server_port":443,"uuid":"c0ffee00-0000-4000-8000-000000000021"}]}`)
	require.Len(t, servers, 1, "the relay of another is not a server of its own")
	server := servers["T"]
	require.True(t, server.Usable(), server.Reason)
	require.Equal(t, []string{
		"the provider connects it through relay; podkop connects it directly",
		"bind_interface is a setting of the provider's app and is left out",
		"domain_resolver is a setting of the provider's app and is left out",
		"domain_strategy is a setting of the provider's app and is left out",
		"fallback_delay is a setting of the provider's app and is left out",
		"routing_mark is a setting of the provider's app and is left out",
		"tls.certificate_path is a setting of the provider's app and is left out",
		"tls.handshake_timeout is a setting of the provider's app and is left out",
	}, server.Notes)
	for _, path := range []string{"detour", "bind_interface", "routing_mark", "domain_resolver", "domain_strategy", "fallback_delay", "tls.certificate_path", "tls.handshake_timeout"} {
		require.Nil(t, outboundAt(t, server, path), path)
	}
	require.Equal(t, "a header, not an option", outboundAt(t, server, "transport.headers.routing_mark"))
	for _, note := range server.Notes {
		require.NotContains(t, note, "SECRET")
		require.NotContains(t, note, "4321")
	}
}

// Groups, direct, block and dns are skipped; a type the links do not carry, an option of another
// syntax and one a link cannot carry give that server a reason, and the rest of the list stays.
func TestSingBoxTypes(t *testing.T) {
	t.Parallel()
	list, err := ParseList(context.Background(), []byte(`{"outbounds":[
		{"type":"selector","tag":"proxy","outbounds":["ok","relay"]},{"type":"urltest","tag":"auto","outbounds":["ok"]},
		{"type":"direct","tag":"direct"},{"type":"block","tag":"block"},{"type":"dns","tag":"dns-out"},
		{"type":"vless","tag":"ok","server":"o.example.net","server_port":443,"uuid":"c0ffee00-0000-4000-8000-000000000022"},
		{"type":"vless","tag":"chained","server":"c.example.net","server_port":443,"uuid":"c0ffee00-0000-4000-8000-000000000023","detour":"relay"},
		{"type":"vless","tag":"relay","server":"r.example.net","server_port":443,"uuid":"c0ffee00-0000-4000-8000-000000000024"},
		{"type":"wireguard","tag":"wg","server":"w.example.net","server_port":51820},
		{"type":"tor","tag":"tor"},
		{"type":"vless","tag":"old","server":"l.example.net","server_port":443,"uuid":"c0ffee00-0000-4000-8000-000000000025","tls":{"enabled":true,"no_such_option":true}},
		{"type":"vless","tag":"bad port","server":"b.example.net","server_port":0,"uuid":"c0ffee00-0000-4000-8000-000000000026"}]}`), realCodec)
	require.NoError(t, err)
	reasons := map[string]string{}
	var names []string
	for _, server := range list.Servers {
		names = append(names, server.Name)
		reasons[server.Name] = server.Reason
	}
	require.Equal(t, []string{"ok", "chained", "relay", "wg", "tor", "old", "bad port"}, names, "a relay a group names is a server too")
	require.Equal(t, 7, list.Outbounds)
	require.Empty(t, reasons["ok"])
	require.Equal(t, "a server of type wireguard is not taken from a subscription", reasons["wg"])
	require.Equal(t, "a server of type tor is not taken from a subscription", reasons["tor"])
	require.Equal(t, "this sing-box has no option no_such_option for the outbound (the syntax of another version, or of another type)", reasons["old"])
	require.Equal(t, "the port of the server is not a port", reasons["bad port"])
}

// The values of options go as sing-box writes them: a list of one as the one value, a text that
// looks like JSON as text, a header of several values as a list.
func TestSingBoxValues(t *testing.T) {
	t.Parallel()
	servers := readSingBoxBody(t, `{"outbounds":[{"type":"vless","tag":"V","server":"v.example.net","server_port":443,"uuid":"c0ffee00-0000-4000-8000-000000000027",
		"tls":{"enabled":true,"server_name":"v.example.net","alpn":["h2"],"certificate":["-----BEGIN CERTIFICATE-----","MIIB","-----END CERTIFICATE-----"]},
		"transport":{"type":"httpupgrade","path":"/h","host":"[v6]","headers":{"X-List":["a","b"],"X-One":["c"]}}}]}`)
	server := servers["V"]
	require.True(t, server.Usable(), server.Reason)
	require.Equal(t, "h2", outboundAt(t, server, "tls.alpn"))
	require.Equal(t, []any{"-----BEGIN CERTIFICATE-----", "MIIB", "-----END CERTIFICATE-----"}, outboundAt(t, server, "tls.certificate"))
	require.Equal(t, "[v6]", outboundAt(t, server, "transport.host"))
	require.Equal(t, []any{"a", "b"}, outboundAt(t, server, "transport.headers.X-List"))
	require.Equal(t, "c", outboundAt(t, server, "transport.headers.X-One"))
	var made map[string]any
	require.NoError(t, json.Unmarshal(server.outbound, &made))
	require.NotContains(t, made, "tag")
}

// A VMess security the decoder would read as auto is the configuration's, set by its path, and no
// note names a parameter the user never saw.
func TestSingBoxVMessSecurity(t *testing.T) {
	t.Parallel()
	for _, security := range []string{"none", "zero", "aes-128-gcm"} {
		servers := readSingBoxBody(t, `{"outbounds":[{"type":"vmess","tag":"V","server":"v.example.net","server_port":443,"uuid":"c0ffee00-0000-4000-8000-000000000046","security":"`+security+`"}]}`)
		server := servers["V"]
		require.True(t, server.Usable(), server.Reason)
		require.Equal(t, security, outboundAt(t, server, "security"), security)
		require.Empty(t, server.Notes, security)
	}
}
