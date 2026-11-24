//go:build with_quic && with_utls && with_clash_api

package plan_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/podkop-net/podkop-experimental/src/backend/plan"
	"github.com/podkop-net/podkop-experimental/src/backend/render"
)

func init() {
	goldenEngineCheck = checkWithEngine
}

// slimLeftOut are the outbounds the build of the package leaves out (podkop_slim: the fork's
// include/podkop_full.go); none in the full build (golden_slim_test.go).
var slimLeftOut []string

// checkWithEngine has sing-box build the configuration of a case as the supervisor has it built
// before a start (Engine.Check: render.Check): built again with its rule-set files in a directory
// of its own and the local lists at their places under it, as supervisor.prepare stages them. It
// tells whether the case was checked (a configuration with an outbound this build leaves out is
// not) and why sing-box refuses the configuration, if it does.
func checkWithEngine(t *testing.T, c *goldenCase) (checked bool, refusal error) {
	t.Helper()
	read, err := readCase(c)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	for name, content := range c.files {
		inside, isFile := strings.CutPrefix(name, inFiles)
		if !isFile {
			continue
		}
		file := filepath.Join(root, filepath.FromSlash(inside))
		if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	rooted := func(name string) string { return filepath.Join(root, name) }
	staged, err := plan.Build(read.settings, read.facts, c.options(read.servers, filepath.Join(root, "candidate", "rulesets"), rooted))
	if err != nil {
		t.Fatal(err)
	}
	if missing := leftOutOfBuild(staged.Config); missing != "" {
		t.Logf("not checked by sing-box: this build has no %s outbound", missing)
		return false, nil
	}
	for _, name := range staged.FileOrder {
		if err := render.WriteFile(name, staged.Files[name]); err != nil {
			t.Fatal(err)
		}
	}
	notes, err := render.Check(staged.Config, staged.Links)
	for _, note := range notes {
		t.Logf("a note of sing-box: %s", note)
	}
	return true, err
}

// leftOutOfBuild is the type of an outbound of the configuration this build leaves out, if any.
func leftOutOfBuild(config []byte) string {
	var document struct {
		Outbounds []struct {
			Type string `json:"type"`
		} `json:"outbounds"`
	}
	if json.Unmarshal(config, &document) != nil {
		return ""
	}
	for _, outbound := range document.Outbounds {
		if slices.Contains(slimLeftOut, outbound.Type) {
			return outbound.Type
		}
	}
	return ""
}
