package subscription

import (
	"os"
	"regexp"
	"runtime/debug"
	"strings"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/stretchr/testify/require"
)

// Each preset sends its app's User-Agent (design §1.1), the device headers of the router whatever
// it is; podkop's own sends podkop/<version>.
func TestPresetHeaders(t *testing.T) {
	t.Parallel()
	device := Device{HWID: "0123456789abcdef0123456789abcdef", Model: "Xiaomi AX3000T", Release: "24.10.4"}
	for preset, want := range map[string]string{
		"":         "podkop/0.8.21",
		"podkop":   "podkop/0.8.21",
		"happ":     "Happ/4.8.3/Linux",
		"incy":     "INCY/3.9.1/linux",
		"sing-box": "SFA (sing-box " + singBoxVersion("unknown") + "; language en_US)",
	} {
		custom, problems := ParseRequest(preset, "", nil, "")
		require.Empty(t, problems, preset)
		header := device.Headers("0.8.21", custom)
		require.Equal(t, want, header.Get("User-Agent"), preset)
		require.Equal(t, device.HWID, header.Get("x-hwid"), preset)
		require.Equal(t, "OpenWrt", header.Get("x-device-os"), preset)
		require.Equal(t, "Xiaomi AX3000T", header.Get("x-device-model"), preset)
		require.Equal(t, preset == "" || preset == "podkop", custom.Empty(), preset)
	}
}

// SFA's User-Agent carries the version of the engine's sing-box, not a literal: the constant of a
// build without podkop's part, else the version of the module go.mod requires.
func TestPresetSingBoxVersion(t *testing.T) {
	t.Parallel()
	require.Equal(t, "1.14.4", singBoxVersion("1.14.4-pdk-209086dbd08a"))
	require.Equal(t, "1.15.0-alpha.2", singBoxVersion("1.15.0-alpha.2"))
	// a build without the version (ldflags) takes the version go.mod requires, where the binary
	// tells its modules (a test binary does not)
	module := "unknown"
	if info, found := debug.ReadBuildInfo(); found {
		for _, dependency := range info.Deps {
			if dependency.Path == "github.com/sagernet/sing-box" {
				module = strings.TrimPrefix(dependency.Version, "v")
			}
		}
	}
	require.Equal(t, module, singBoxVersion("unknown"))
	required := ""
	content, err := os.ReadFile("../go.mod")
	require.NoError(t, err)
	for _, line := range strings.Split(string(content), "\n") {
		if fields := strings.Fields(line); len(fields) == 2 && fields[0] == "github.com/sagernet/sing-box" {
			required = strings.TrimPrefix(fields[1], "v")
		}
	}
	require.Regexp(t, `^[0-9]+\.[0-9]+\.[0-9]+$`, required)
	require.Equal(t, "SFA (sing-box "+required+"; language en_US)", "SFA (sing-box "+singBoxVersion(required+"-pdk-209086dbd08a")+"; language en_US)")
	require.Equal(t, "SFA (sing-box "+singBoxVersion("")+"; language en_US)", singBoxAgent(""))
	// the program gives the version of the engine's sing-box, a test build has none of its own
	require.Equal(t, "unknown", C.Version, "a test build has no version of its own")
	require.Regexp(t, regexp.MustCompile(`^SFA \(sing-box [^;]+; language en_US\)$`), singBoxAgent(C.Version))
	// Remnawave's default rules give sing-box JSON to this name (any case): ^sfa|sfi|sfm|sft|karing|singbox
	require.Regexp(t, regexp.MustCompile(`(?i)^(sfa|sfi|sfm|sft|karing|singbox)`), singBoxAgent(C.Version))
	// the preset sends the version it is given, a build's without podkop's part
	sent, problems := ParseRequest(PresetSingBox, "", nil, "1.14.4-pdk-209086dbd08a")
	require.Empty(t, problems)
	require.Equal(t, Custom{Preset: PresetSingBox, UserAgent: "SFA (sing-box 1.14.4; language en_US)"}, sent)
}

// A User-Agent without a preset is custom, as is custom with it; a preset of an app or podkop does
// not send the option user_agent; custom with none is podkop's own.
func TestPresetCustom(t *testing.T) {
	t.Parallel()
	typed, problems := ParseRequest("", "  INCY/4.0.3/android  ", nil, "")
	require.Empty(t, problems)
	require.Equal(t, Custom{UserAgent: "INCY/4.0.3/android"}, typed)
	custom, problems := ParseRequest("custom", "INCY/4.0.3/android", nil, "")
	require.Empty(t, problems)
	require.Equal(t, typed, custom)
	require.Equal(t, typed.Key(), custom.Key())
	old, _ := ParseCustom("INCY/4.0.3/android", nil)
	require.Equal(t, typed, old)

	happ, problems := ParseRequest("happ", "INCY/4.0.3/android", nil, "")
	require.Empty(t, problems)
	require.Equal(t, Custom{Preset: "happ", UserAgent: "Happ/4.8.3/Linux"}, happ, "the User-Agent of another preset is not sent")

	for _, preset := range []string{"", "podkop", "custom", " podkop "} {
		own, problems := ParseRequest(preset, "", nil, "")
		require.Empty(t, problems, preset)
		require.True(t, own.Empty(), preset)
		require.Empty(t, own.Key(), preset)
	}
	podkop, _ := ParseRequest("podkop", "INCY", []string{"X-Key: 1"}, "")
	none, _ := ParseRequest("", "", []string{"X-Key: 1"}, "")
	require.Equal(t, none, podkop)
	require.Equal(t, none.Key(), podkop.Key(), "{} and {podkop} are the same request")
	own, _ := ParseRequest("podkop", "INCY", nil, "")
	require.Equal(t, AddressKey("https://a.example/"+token), RequestKey("https://a.example/"+token, own), "podkop's own is keyed by the address alone")
}

// A preset podkop does not know is a problem of the User-Agent's line: podkop's own is sent, the
// headers are.
func TestPresetUnknown(t *testing.T) {
	t.Parallel()
	custom, problems := ParseRequest("v2rayN", "x", []string{"X-Key: 1"}, "")
	require.Len(t, problems, 1)
	require.Equal(t, Problem{Line: 0, Code: "preset", Text: "the preset is not one podkop knows"}, problems[0])
	require.Empty(t, custom.UserAgent)
	require.Empty(t, custom.Preset)
	require.Equal(t, []string{"X-Key"}, custom.Names())
	require.Equal(t, "podkop/0.8.21", Device{}.Headers("0.8.21", custom).Get("User-Agent"))
	require.Equal(t, "the User-Agent of the settings is not sent (the preset is not one podkop knows)", problems[0].Describe())
	require.NotContains(t, problems[0].Describe(), "v2rayN")
}

// The key of a request is what is sent: a preset and the same User-Agent typed are the same
// request; another preset is another.
func TestPresetKeys(t *testing.T) {
	t.Parallel()
	happ, _ := ParseRequest("happ", "", nil, "")
	typed, _ := ParseRequest("custom", "Happ/4.8.3/Linux", nil, "")
	incy, _ := ParseRequest("incy", "", nil, "")
	require.Equal(t, happ.Key(), typed.Key())
	require.NotEqual(t, happ.Key(), incy.Key())
	address := "https://a.example/sub/" + token
	require.NotEqual(t, AddressKey(address), RequestKey(address, happ))
	require.Equal(t, RequestKey(address, happ), RequestKey(address, typed))
}

// The log and the global check name the preset and its User-Agent; podkop's own is not named.
func TestPresetAskedAs(t *testing.T) {
	t.Parallel()
	for _, test := range []struct{ preset, agent, want string }{
		{"", "", ""},
		{"happ", "Happ/4.8.3/Linux", "asked as Happ (Happ/4.8.3/Linux)"},
		{"incy", "INCY/3.9.1/linux", "asked as INCY (INCY/3.9.1/linux)"},
		{"sing-box", "SFA (sing-box 1.14.4; language en_US)", "asked as sing-box (SFA) (SFA (sing-box 1.14.4; language en_US))"},
		{"", "INCY", "User-Agent INCY"},
		{"custom", "INCY", "User-Agent INCY"},
	} {
		require.Equal(t, test.want, AskedAs(test.preset, test.agent), test.preset)
	}
}

// The answer to a preset that podkop cannot read is told as the answer to its User-Agent.
func TestPresetForAgent(t *testing.T) {
	t.Parallel()
	happ, _ := ParseRequest("happ", "", nil, "")
	address := "https://a.example/sub/" + token
	for code, want := range map[string]string{"json": "json-agent", "clash": "clash-agent", "happ-crypt": "happ-crypt-agent", "nolinks": "nolinks-agent"} {
		failure := ForAgent(fail(code, true, "x"), happ, address).(*Failure)
		require.Equal(t, want, failure.Code)
		require.Contains(t, failure.Text, `"Happ/4.8.3/Linux"`)
		require.True(t, failure.Final())
	}
	own, _ := ParseRequest("podkop", "", nil, "")
	require.Equal(t, "happ-crypt", ForAgent(fail("happ-crypt", true, "x"), own, address).(*Failure).Code)
}
