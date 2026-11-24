// Package render writes what a start of the backend needs before sing-box runs: the
// sing-box configuration and the rule-set files, made of the backend's UCI file. It has
// no effect besides those files.
package render

import (
	"bytes"
	"cmp"
	"os"
	"path/filepath"

	"github.com/podkop-net/podkop-experimental/src/backend/engine"
	"github.com/podkop-net/podkop-experimental/src/backend/model"
	"github.com/podkop-net/podkop-experimental/src/backend/plan"
	"github.com/podkop-net/podkop-experimental/src/backend/uci"
	E "github.com/sagernet/sing/common/exceptions"
)

// Request says what to read and where to write.
type Request struct {
	// UCIPath is the settings file, /etc/config/podkop on a router.
	UCIPath string
	// Facts are what is known of the router besides the settings.
	Facts plan.Facts
	// OutputPath is where the configuration goes.
	OutputPath string
	// RuleSetDir is where the rule-set files go; the backend's usual place when empty.
	RuleSetDir string
	// Root is put before every path that is read or written, the settings file excepted:
	// a test and a comparison run keep the files of a case under a directory while the
	// configuration names the paths of a router.
	Root string
	// SkipCheck leaves out the building of the result by sing-box.
	SkipCheck bool
}

// Outcome is what was done.
type Outcome struct {
	// ConfigPath is the configuration file, with Root.
	ConfigPath string
	// Changed tells whether the configuration differs from the one that was there.
	Changed bool
	// Warnings are for the log.
	Warnings []string
}

// Run reads the settings, builds the configuration, stores the rule-set files, checks the
// configuration with sing-box and stores it. A configuration that does not pass the check
// is not stored: the one in place stays.
func Run(request Request) (*Outcome, error) {
	content, err := os.ReadFile(request.UCIPath)
	if err != nil {
		return nil, E.Cause(err, "read the settings")
	}
	parsed, err := uci.Parse(content)
	if err != nil {
		return nil, E.Cause(err, "read the settings")
	}
	config, err := model.Load(parsed)
	if err != nil {
		return nil, E.Cause(err, "read the settings")
	}
	outputPath := request.OutputPath
	if outputPath == "" {
		return nil, E.New("no path for the configuration")
	}
	rooted := func(path string) string {
		if request.Root == "" {
			return path
		}
		return filepath.Join(request.Root, path)
	}
	result, err := plan.Build(config, request.Facts, plan.Options{
		RuleSetDir: request.RuleSetDir,
		ReadFile:   func(path string) ([]byte, error) { return os.ReadFile(rooted(path)) },
		CheckList:  engine.CheckRuleSet,
		DecodeLink: engine.DecodeLink,
	})
	if err != nil {
		return nil, err
	}
	outcome := &Outcome{ConfigPath: rooted(outputPath), Warnings: result.Warnings}
	for _, path := range result.FileOrder {
		err = WriteFile(rooted(path), result.Files[path])
		if err != nil {
			return nil, E.Cause(err, "write the rule-set")
		}
	}
	if !request.SkipCheck {
		checked := result.Config
		if request.Root != "" {
			// the files of this run are under the root, the configuration names them
			// where a router has them
			again, err := plan.Build(config, request.Facts, plan.Options{
				RuleSetDir: rooted(cmp.Or(request.RuleSetDir, plan.DefaultRuleSetDir)),
				ReadFile:   func(path string) ([]byte, error) { return os.ReadFile(rooted(path)) },
				CheckList:  engine.CheckRuleSet,
				LocalPath:  rooted,
				DecodeLink: engine.DecodeLink,
			})
			if err != nil {
				return nil, err
			}
			checked = again.Config
		}
		notes, err := Check(checked, result.Links)
		if err != nil {
			return nil, err
		}
		for _, note := range notes {
			outcome.Warnings = append(outcome.Warnings, note)
		}
	}
	current, err := os.ReadFile(outcome.ConfigPath)
	if err == nil && bytes.Equal(current, result.Config) {
		return outcome, nil
	}
	err = WriteFile(outcome.ConfigPath, result.Config)
	if err != nil {
		return nil, E.Cause(err, "write the configuration")
	}
	outcome.Changed = true
	return outcome, nil
}

// Check builds a configuration made of the settings as sing-box will run it, the rule-set
// files it names included, and returns what sing-box notes about it (engine.Check). The
// outbounds of the proxy links are built there with the rest, once: when sing-box refuses
// the configuration, the links are built one by one to name the one it cannot use, with
// what the link keeps secret left out of the message. The words of sing-box about the
// whole configuration are given when each link builds alone.
func Check(config []byte, uses []plan.Link) ([]string, error) {
	notes, err := engine.Check(config)
	if err == nil {
		return notes, nil
	}
	for _, use := range uses {
		linkErr := engine.CheckLink(use.Text)
		if linkErr != nil {
			return nil, E.Cause(linkErr, "section ", use.Section, ": cannot use the proxy link of ", use.Name)
		}
	}
	return nil, E.Cause(err, "sing-box does not take the configuration")
}

// WriteFile puts a file in place whole: written beside it and renamed. A reader, sing-box
// watching a rule-set file among them, sees the old content or the new one.
func WriteFile(path string, content []byte) error {
	err := os.MkdirAll(filepath.Dir(path), 0o755)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	_, err = temporary.Write(content)
	if err == nil {
		err = temporary.Chmod(0o600)
	}
	closeErr := temporary.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(temporary.Name(), path)
	}
	if err != nil {
		os.Remove(temporary.Name())
	}
	return err
}
