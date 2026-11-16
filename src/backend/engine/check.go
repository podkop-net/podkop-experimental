// Package engine is the backend's way to sing-box itself: the one place that builds an
// instance of it.
package engine

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/experimental/deprecated"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
)

// buildTimeout bounds the building of an instance: milliseconds as a rule, but sing-box
// reads the local lists while it builds, and a big list in JSON that its fast reader leaves
// to the decoder takes seconds on a slow router. A bound for a build that hangs, not one a
// valid list may reach.
var buildTimeout = 60 * time.Second

// notes collects what sing-box would report as deprecated while it builds and starts: the
// manager of a run prints such a note, and for one about to be removed ends the process.
// sing-box reports from more than one goroutine at a time: rule sets start five at once.
// With tell, each note is also one of the process (Notes).
type notes struct {
	tell   bool
	access sync.Mutex
	list   []string
}

func (n *notes) ReportDeprecated(feature deprecated.Note) {
	message := feature.Message()
	n.access.Lock()
	n.list = append(n.list, message)
	n.access.Unlock()
	if n.tell {
		told.add(message)
	}
}

func (n *notes) taken() []string {
	n.access.Lock()
	defer n.access.Unlock()
	return append([]string(nil), n.list...)
}

// told are the notes of the process: those of the checks of whole configurations and of
// the instances, each once. A configuration that is applied again brings the same notes
// again, and the log is to have each once.
var told = &noteSet{seen: make(map[string]bool)}

type noteSet struct {
	access sync.Mutex
	seen   map[string]bool
	fresh  []string
}

func (s *noteSet) add(message string) {
	s.access.Lock()
	defer s.access.Unlock()
	if !s.seen[message] {
		s.seen[message] = true
		s.fresh = append(s.fresh, message)
	}
}

// Notes returns the notes sing-box made that were not returned before, each once in the
// life of the process: options of a configuration that are deprecated, noted by Check or
// by an instance while it was built or started. The checks of single outbounds
// (CheckOutbound) keep theirs to themselves.
func Notes() []string {
	told.access.Lock()
	defer told.access.Unlock()
	fresh := told.fresh
	told.fresh = nil
	return fresh
}

// Check builds a configuration the way "sing-box check" does and closes what it built:
// the options are decoded by sing-box's own decoder and every outbound, rule and rule
// set is created. Nothing is listened on or dialed. It returns what sing-box notes about
// the configuration (options that are deprecated).
func Check(configuration []byte) ([]string, error) {
	return guarded(func() ([]string, error) {
		return build(configuration, true)
	})
}

// CheckOutbound builds one outbound, as the only one of a configuration: an outbound that
// passes is one this very sing-box takes, with the protocols and the options it was built
// with.
func CheckOutbound(outbound []byte) ([]string, error) {
	return guarded(func() ([]string, error) {
		configuration := append(append([]byte(`{"log":{"disabled":true},"outbounds":[`), outbound...), "]}"...)
		list, err := build(configuration, false)
		if err != nil {
			message := err.Error()
			for _, prefix := range []string{"outbounds[0].", "initialize outbound[0]: ", "create client transport: "} {
				message = strings.TrimPrefix(message, prefix)
			}
			return nil, E.New(message)
		}
		return list, nil
	})
}

func build(configuration []byte, tell bool) ([]string, error) {
	collected := &notes{tell: tell}
	ctx, cancel := context.WithCancel(service.ExtendContext(boxContext(service.ContextWith[deprecated.Manager](context.Background(), collected))))
	defer cancel()
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, configuration)
	if err != nil {
		return nil, err
	}
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		return nil, err
	}
	instance.Close()
	return collected.taken(), nil
}

// guarded runs a build apart: code that is given what a link or a hand-written outbound
// says may fail on it or wait for it, and that is a configuration that cannot be used,
// not the end of the backend.
func guarded(run func() ([]string, error)) ([]string, error) {
	type built struct {
		notes []string
		err   error
	}
	done := make(chan built, 1)
	go func() {
		var result built
		defer func() {
			if recover() != nil {
				result = built{nil, E.New("this sing-box cannot build the configuration")}
			}
			done <- result
		}()
		result.notes, result.err = run()
	}()
	select {
	case result := <-done:
		return result.notes, result.err
	case <-time.After(buildTimeout):
		return nil, E.New("this sing-box takes too long to build the configuration")
	}
}
