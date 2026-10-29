package ctl

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/podkop-net/podkop-experimental/src/backend/api"
	"github.com/podkop-net/podkop-experimental/src/backend/logbuf"
	"github.com/podkop-net/podkop-experimental/src/backend/model"

	"github.com/stretchr/testify/require"
)

// The test of the outbounds names the section each section connects through, beside what it
// says of a group; a section without one reads as before.
func TestOutboundLinesTellTheTransit(t *testing.T) {
	clash := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case request.URL.Path == "/proxies":
			_, _ = writer.Write([]byte(`{"proxies": {
				"main-out": {"type": "Socks"},
				"entry-out": {"type": "Socks"},
				"sel-out": {"type": "Selector", "now": "sel-1-out", "all": ["sel-1-out", "sel-2-out"]},
				"ut-out": {"type": "URLTest", "now": "ut-1-out", "all": ["ut-1-out"]},
				"yt-out": {"type": "Selector", "now": "block", "all": ["block"]},
				"tv-out": {"type": "Selector", "now": "block-out", "all": ["block-out"]},
				"direct-out": {"type": "Direct"}}}`))
		case strings.HasPrefix(request.URL.Path, "/proxies/"):
			_, _ = writer.Write([]byte(`{"delay": 120}`))
		case request.URL.Path == "/group/sel-out/delay":
			_, _ = writer.Write([]byte(`{"sel-1-out": 150}`))
		case request.URL.Path == "/group/ut-out/delay":
			_, _ = writer.Write([]byte(`{}`))
		case request.URL.Path == "/group/tv-out/delay":
			_, _ = writer.Write([]byte(`{"block-out": 90}`))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer clash.Close()
	running := &backend{facts: api.Facts{ClashAPI: strings.TrimPrefix(clash.URL, "http://")}}
	caller := &clashCaller{client: api.Client{Path: serve(t, running, logbuf.New(1<<12))}}
	lines := outboundLines(caller, []model.Section{
		{Name: "main", ConnectionType: "proxy", Detour: "entry"},
		{Name: "entry", ConnectionType: "proxy"},
		{Name: "sel", ConnectionType: "proxy", Detour: "entry"},
		{Name: "ut", ConnectionType: "proxy", Detour: "awg"},
		// a group with no server that refuses; one that goes as the section named block; one the
		// configuration that runs does not have yet
		{Name: "yt", ConnectionType: "group"},
		{Name: "tv", ConnectionType: "group"},
		{Name: "new", ConnectionType: "group"},
	})
	require.Equal(t, []string{
		"✅ main (via entry): 120 ms",
		"✅ entry: 120 ms",
		"✅ sel (via entry, selector, sel-1-out): 150 ms",
		"❌ ut (via awg, urltest): none of its outbounds answers",
		"✅ tv (selector, block-out): 90 ms",
		"✅ direct (without a proxy): 120 ms",
		"⛔ yt: its group chooses no server, and its connections are refused",
	}, lines)
}
