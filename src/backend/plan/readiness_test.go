package plan

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/podkop-net/podkop-experimental/src/backend/dataplane"
	"github.com/podkop-net/podkop-experimental/src/backend/model"
	"github.com/podkop-net/podkop-experimental/src/backend/uci"

	"github.com/stretchr/testify/require"
)

// Every configuration answers the readiness name from FakeIP: the
// supervisor tells by it that a started sing-box is up. Whatever the settings, each DNS rule an A question for the name may match
// before the first one it surely matches routes it to the FakeIP server, and so does that
// one; the server answers from dataplane.FakeIPRange.
func TestReadinessNameIsAnsweredFromFakeIP(t *testing.T) {
	const head = "config settings 'settings'\n\toption dns_type 'udp'\n\toption dns_server '8.8.8.8'\n"
	const proxy = "\nconfig section 'main'\n\toption connection_type 'proxy'\n\toption proxy_config_type 'url'\n\toption proxy_string 'socks5://203.0.113.15:1080'\n"
	for name, settings := range map[string]string{
		"a proxy without lists": head + proxy,
		"user domains and a community list": head + proxy + "\toption user_domain_list_type 'dynamic'\n\tlist user_domains 'one.example'\n\tlist user_domains '" + dataplane.ReadinessName + "'\n" +
			"\tlist community_lists 'youtube'\n",
		"a section that blocks": head + proxy + "\nconfig section 'blocked'\n\toption connection_type 'block'\n\toption user_domain_list_type 'dynamic'\n\tlist user_domains 'two.example'\n",
		"an excluded domain":    head + proxy + "\nconfig section 'direct'\n\toption connection_type 'exclusion'\n\toption user_domain_list_type 'dynamic'\n\tlist user_domains '" + dataplane.ReadinessName + "'\n",
	} {
		// no check names, others, and those the readiness name is one of
		_, suffix, _ := strings.Cut(dataplane.ReadinessName, ".")
		for _, checkNames := range []CheckNames{{}, {Suffix: "check.invalid", DeadEndAddress: "127.0.0.1", DeadEndPort: 9},
			{Suffix: suffix, DeadEndAddress: "127.0.0.1", DeadEndPort: 9}} {
			parsed, err := uci.Parse([]byte(settings))
			require.NoError(t, err, name)
			config, err := model.Load(parsed)
			require.NoError(t, err, name)
			result, err := Build(config, Facts{}, Options{
				CheckNames: checkNames,
				DecodeLink: func(string) ([]byte, []string, error) {
					return []byte(`{"type": "socks", "server": "203.0.113.15", "server_port": 1080}`), nil, nil
				},
			})
			require.NoError(t, err, name)
			var document struct {
				DNS struct {
					Servers []map[string]any `json:"servers"`
					Rules   []map[string]any `json:"rules"`
				} `json:"dns"`
			}
			require.NoError(t, json.Unmarshal(result.Config, &document), name)
			fakeIPServer := ""
			for _, server := range document.DNS.Servers {
				if server["type"] == "fakeip" {
					require.Equal(t, dataplane.FakeIPRange, server["inet4_range"], name)
					fakeIPServer, _ = server["tag"].(string)
				}
			}
			require.NotEmpty(t, fakeIPServer, name)
			answered := false
			for index, rule := range document.DNS.Rules {
				may, surely := matchesReadiness(rule)
				if !may {
					continue
				}
				require.Equal(t, "route", rule["action"], "%s: rule %d", name, index)
				require.Equal(t, fakeIPServer, rule["server"], "%s: rule %d", name, index)
				if surely {
					answered = true
					break
				}
			}
			require.True(t, answered, "%s: no DNS rule surely matches %s", name, dataplane.ReadinessName)
		}
	}
}

// matchesReadiness tells whether a DNS rule may match an A question for the readiness
// name, and whether it surely does. A condition this test does not know may match.
func matchesReadiness(rule map[string]any) (may bool, surely bool) {
	surely = true
	for key, value := range rule {
		switch key {
		case "action", "server", "rewrite_ttl":
		case "query_type":
			if !slices.Contains(texts(value), "A") {
				return false, false
			}
		case "domain":
			if !slices.Contains(texts(value), dataplane.ReadinessName) {
				return false, false
			}
		case "domain_suffix":
			found := false
			for _, suffix := range texts(value) {
				suffix = strings.TrimPrefix(suffix, ".")
				if dataplane.ReadinessName == suffix || strings.HasSuffix(dataplane.ReadinessName, "."+suffix) {
					found = true
				}
			}
			if !found {
				return false, false
			}
		default:
			surely = false
		}
	}
	return true, surely
}

func texts(value any) []string {
	switch typed := value.(type) {
	case string:
		return []string{typed}
	case []any:
		var result []string
		for _, item := range typed {
			if text, isText := item.(string); isText {
				result = append(result, text)
			}
		}
		return result
	}
	return nil
}
