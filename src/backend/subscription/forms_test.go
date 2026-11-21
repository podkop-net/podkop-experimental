package subscription

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/podkop-net/podkop-experimental/src/backend/engine"
	"github.com/stretchr/testify/require"
)

// The tests of the formats read the servers with the engine's own decoder, as the backend does:
// a change of the grammar of the links in the engine fails them.

// realDecode is the decoder of the backend, realCodec what the readers of the backend ask the
// engine.
var (
	realDecode Decoder = engine.DecodeLink
	realCodec          = Codec{Decode: engine.DecodeLink, Normalize: engine.NormalizeOutbound}
)

// dumpForms makes TestDumpForms print what the readers make of the fixtures (go test -run
// TestDumpForms ./subscription/ -args -dump), gzip and base64 on one line of the log: the
// goldens and the differences of the Remnawave cases are written from it, and looked at.
var dumpForms = flag.Bool("dump", false, "print what the readers make of the fixtures")

// readResult is a list as the goldens keep it.
type readResult struct {
	Format    string       `json:"format,omitempty"`
	Configs   int          `json:"configs,omitempty"`
	Outbounds int          `json:"outbounds,omitempty"`
	Error     string       `json:"error,omitempty"`
	ErrorArgs []string     `json:"error_args,omitempty"`
	Servers   []readServer `json:"servers,omitempty"`
}

type readServer struct {
	Name     string          `json:"name"`
	ID       string          `json:"id,omitempty"`
	Reason   string          `json:"reason,omitempty"`
	Notes    []string        `json:"notes,omitempty"`
	Link     string          `json:"link,omitempty"`
	Outbound json.RawMessage `json:"outbound,omitempty"`
}

// readBody reads a body as the backend does.
func readBody(body []byte) (readResult, List) {
	list, err := ParseList(context.Background(), body, realCodec)
	result := readResult{Format: list.Format, Configs: list.Configs, Outbounds: list.Outbounds}
	var failure *Failure
	if errors.As(err, &failure) {
		result.Error, result.ErrorArgs = failure.Code, failure.Args
		return result, list
	}
	for index := range list.Servers {
		server := &list.Servers[index]
		result.Servers = append(result.Servers, readServer{Name: server.Name, ID: server.ID, Reason: server.Reason, Notes: server.Notes, Link: server.Link, Outbound: server.outbound})
	}
	return result, list
}

func readFixture(t *testing.T, path string) readResult {
	body, err := os.ReadFile(path)
	require.NoError(t, err)
	result, _ := readBody(body)
	return result
}

func goldenText(t *testing.T, value any) string {
	content, err := json.MarshalIndent(value, "", "  ")
	require.NoError(t, err)
	return string(content) + "\n"
}

// The fixtures of testdata/xray and testdata/singbox read to their goldens: the servers, their
// names, IDs, reasons and notes, the links podkop made and the outbounds the engine decodes them
// to.
func TestFormGoldens(t *testing.T) {
	t.Parallel()
	for _, directory := range []string{"testdata/xray", "testdata/singbox"} {
		files, err := filepath.Glob(filepath.Join(directory, "*.json"))
		require.NoError(t, err)
		require.NotEmpty(t, files)
		for _, file := range files {
			content, err := os.ReadFile(strings.TrimSuffix(file, ".json") + ".golden")
			require.NoError(t, err, file)
			var want, got any
			require.NoError(t, json.Unmarshal(content, &want), file)
			require.NoError(t, json.Unmarshal([]byte(goldenText(t, readFixture(t, file))), &got), file)
			require.Equal(t, want, got, file)
		}
	}
}

// TestDumpForms prints what the readers make of the fixtures; it runs with -dump only.
func TestDumpForms(t *testing.T) {
	if !*dumpForms {
		t.Skip("-dump only")
	}
	dump := map[string]any{}
	for _, directory := range []string{"testdata/xray", "testdata/singbox"} {
		files, _ := filepath.Glob(filepath.Join(directory, "*.json"))
		for _, file := range files {
			dump[file] = readFixture(t, file)
		}
	}
	cases, _ := filepath.Glob("testdata/remnawave/*")
	for _, directory := range cases {
		forms := map[string]readResult{}
		for form, file := range remnawaveFiles {
			body, err := os.ReadFile(filepath.Join(directory, file))
			if err == nil {
				forms[form], _ = readBody(body)
			}
		}
		dump[directory] = map[string]any{"forms": forms, "differences": remnawaveDifferences(forms)}
	}
	content, err := json.Marshal(dump)
	require.NoError(t, err)
	var packed bytes.Buffer
	writer := gzip.NewWriter(&packed)
	_, _ = writer.Write(content)
	_ = writer.Close()
	t.Logf("DUMP %s", base64.StdEncoding.EncodeToString(packed.Bytes()))
	t.Fail()
}

// The bodies of a case of Remnawave's generators (lab/v0821/rwgen of the workspace).
var remnawaveFiles = map[string]string{"links": "links.txt", "xray": "xray.json", "singbox": "singbox.json", "extended": "links.extended.txt", "xrayext": "xray.extended.json"}

// remnawaveExpect is what a case expects of the forms, beyond the same servers as the links:
// expect.json of the case.
type remnawaveExpect struct {
	Why string `json:"why"`
	// Errors are the failures of the forms that are refused, by the form
	Errors map[string]string `json:"errors,omitempty"`
	// Servers are what differs for a server, by its name and the form
	Servers map[string]map[string]remnawaveServer `json:"servers,omitempty"`
}

type remnawaveServer struct {
	// Missing tells that the form has no such server (a generator skips the host)
	Missing bool `json:"missing,omitempty"`
	// Differ are the options of the outbound that differ from the link's (paths)
	Differ []string `json:"differ,omitempty"`
	// Reason is a part of the reason the server of the form has (the link's has none, or
	// another)
	Reason string `json:"reason,omitempty"`
	// Notes are parts of notes the server of the form has
	Notes []string `json:"notes,omitempty"`
	Why   string   `json:"why,omitempty"`
}

// remnawaveDifferences is how the servers of the forms differ from those of the links, by name:
// missing, the paths of the options that differ, the reasons.
func remnawaveDifferences(forms map[string]readResult) map[string]map[string]remnawaveServer {
	differences := map[string]map[string]remnawaveServer{}
	byName := func(result readResult) map[string]readServer {
		servers := map[string]readServer{}
		for _, server := range result.Servers {
			servers[server.Name] = server
		}
		return servers
	}
	links := byName(forms["links"])
	names := map[string]bool{}
	for form, result := range forms {
		if form == "extended" || form == "xrayext" {
			continue
		}
		for name := range byName(result) {
			names[name] = true
		}
	}
	for name := range names {
		reference, hasReference := links[name]
		for _, form := range []string{"links", "xray", "singbox"} {
			result, read := forms[form]
			if !read || result.Error != "" {
				continue
			}
			server, found := byName(result)[name]
			difference := remnawaveServer{}
			switch {
			case !found:
				difference.Missing = true
			case form == "links":
				difference.Reason = server.Reason
			case !hasReference:
				difference.Differ = []string{"(no link)"}
				difference.Reason = server.Reason
			default:
				difference.Differ = outboundPaths(reference.Outbound, server.Outbound)
				if server.Reason != reference.Reason {
					difference.Reason = server.Reason
				}
			}
			if difference.Missing || len(difference.Differ) > 0 || difference.Reason != "" {
				if differences[name] == nil {
					differences[name] = map[string]remnawaveServer{}
				}
				differences[name][form] = difference
			}
		}
	}
	return differences
}

// outboundPaths are the paths of the options in which two outbounds differ.
func outboundPaths(left json.RawMessage, right json.RawMessage) []string {
	flat := func(content json.RawMessage) map[string]string {
		values := map[string]string{}
		var tree any
		if json.Unmarshal(content, &tree) != nil {
			return values
		}
		var walk func(path string, value any)
		walk = func(path string, value any) {
			if node, isObject := value.(map[string]any); isObject {
				for key, child := range node {
					walk(strings.TrimPrefix(path+"."+key, "."), child)
				}
				return
			}
			text, _ := json.Marshal(value)
			values[path] = string(text)
		}
		walk("", tree)
		return values
	}
	leftValues, rightValues := flat(left), flat(right)
	paths := map[string]bool{}
	for path, value := range leftValues {
		if rightValues[path] != value {
			paths[path] = true
		}
	}
	for path, value := range rightValues {
		if leftValues[path] != value {
			paths[path] = true
		}
	}
	var list []string
	for path := range paths {
		list = append(list, path)
	}
	sort.Strings(list)
	return list
}

// Differential, by Remnawave's own generators (refs/remnawave-backend 6853666, lab/v0821/rwgen):
// for each synthetic host the servers of its Xray JSON and of its sing-box JSON decode to the
// outbound of the server of its link, or the difference is the one expect.json lists and
// explains.
func TestRemnawaveForms(t *testing.T) {
	t.Parallel()
	cases, err := filepath.Glob("testdata/remnawave/*")
	require.NoError(t, err)
	require.NotEmpty(t, cases)
	for _, directory := range cases {
		content, err := os.ReadFile(filepath.Join(directory, "expect.json"))
		require.NoError(t, err, directory)
		var expect remnawaveExpect
		require.NoError(t, json.Unmarshal(content, &expect), directory)
		require.NotEmpty(t, expect.Why, directory)
		forms := map[string]readResult{}
		for form, file := range remnawaveFiles {
			body, err := os.ReadFile(filepath.Join(directory, file))
			if err == nil {
				forms[form], _ = readBody(body)
			}
		}
		for _, form := range []string{"links", "xray", "singbox"} {
			require.Equal(t, expect.Errors[form], forms[form].Error, "%s %s", directory, form)
		}
		require.Equal(t, "", forms["links"].Format, directory)
		if forms["xray"].Error == "" {
			require.Equal(t, FormatXray, forms["xray"].Format, directory)
		}
		if forms["singbox"].Error == "" {
			require.Equal(t, FormatSingBox, forms["singbox"].Format, directory)
		}
		got := remnawaveDifferences(forms)
		for name, byForm := range expect.Servers {
			for form, want := range byForm {
				require.NotEmpty(t, want.Why, "%s %s %s: a difference is explained", directory, name, form)
				have := got[name][form]
				require.Equal(t, want.Missing, have.Missing, "%s %s %s", directory, name, form)
				require.Equal(t, want.Differ, have.Differ, "%s %s %s", directory, name, form)
				if want.Reason != "" {
					require.Contains(t, have.Reason, want.Reason, "%s %s %s", directory, name, form)
				} else {
					require.Empty(t, have.Reason, "%s %s %s", directory, name, form)
				}
				delete(got[name], form)
			}
		}
		for name, byForm := range got {
			for form, have := range byForm {
				t.Errorf("%s: %s %s differs and expect.json does not say so: %+v", directory, name, form, have)
			}
		}
		// the notes a form must have for a server
		for name, byForm := range expect.Servers {
			for form, want := range byForm {
				for _, note := range want.Notes {
					var notes []string
					for _, server := range forms[form].Servers {
						if server.Name == name {
							notes = server.Notes
						}
					}
					require.True(t, containsPart(notes, note), "%s %s %s: a note with %q in %q", directory, name, form, note, notes)
				}
			}
		}
		// the extended clients' bodies: the same servers under the same names
		for form, base := range map[string]string{"extended": "links", "xrayext": "xray"} {
			extended, read := forms[form]
			if !read {
				continue
			}
			require.Equal(t, ids(forms[base]), ids(extended), "%s %s", directory, form)
		}
	}
}

func containsPart(texts []string, part string) bool {
	for _, text := range texts {
		if strings.Contains(text, part) {
			return true
		}
	}
	return false
}

func ids(result readResult) []string {
	var list []string
	for _, server := range result.Servers {
		list = append(list, server.ID+" "+server.Name)
	}
	sort.Strings(list)
	return list
}
