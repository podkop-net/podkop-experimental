//go:build lab

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// parse-list prints the servers of a body with the outbounds the engine runs, tagged with their
// names; a body that is refused is an error line and status 2.
func TestParseList(t *testing.T) {
	directory := t.TempDir()
	body := `[{"remarks":"NL 1","outbounds":[{"tag":"proxy","protocol":"vless","settings":{"address":"nl1.example","port":443,"id":"c0ffee00-0000-4000-8000-000000000031"},
		"streamSettings":{"security":"tls","tlsSettings":{"serverName":"nl1.example"}}},{"tag":"direct","protocol":"freedom"}]},
		{"remarks":"Broken","outbounds":[{"tag":"proxy","protocol":"wireguard","settings":{}}]}]`
	path := filepath.Join(directory, "body.json")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	var output, errorOutput bytes.Buffer
	require.Equal(t, 0, parseList(path, nil, &output, &errorOutput), errorOutput.String())
	var parsed parsedList
	require.NoError(t, json.Unmarshal(output.Bytes(), &parsed))
	require.Equal(t, "xray", parsed.Format)
	require.Equal(t, 2, parsed.Configs)
	require.Len(t, parsed.Servers, 2)
	server := parsed.Servers[0]
	require.Equal(t, "NL 1", server.Name)
	require.True(t, server.Made)
	require.NotEmpty(t, server.ID)
	var outbound map[string]any
	require.NoError(t, json.Unmarshal(server.Outbound, &outbound))
	require.Equal(t, "NL 1", outbound["tag"])
	require.Equal(t, "vless", outbound["type"])
	require.Equal(t, "nl1.example", outbound["server"])
	require.Empty(t, parsed.Servers[1].Outbound)
	require.Contains(t, parsed.Servers[1].Reason, "wireguard")

	output.Reset()
	require.Equal(t, 0, parseList("-", strings.NewReader("vless://c0ffee00-0000-4000-8000-000000000032@a.example:443#A\n"), &output, &errorOutput))
	var links parsedList
	require.NoError(t, json.Unmarshal(output.Bytes(), &links))
	require.Equal(t, "", links.Format)
	require.Len(t, links.Servers, 1)
	require.False(t, links.Servers[0].Made)

	errorOutput.Reset()
	require.Equal(t, 2, parseList("-", strings.NewReader(`{"rules":[]}`), &output, &errorOutput))
	require.Equal(t, "error: the provider sent JSON that is not a configuration of Xray or sing-box\n", errorOutput.String())
}
