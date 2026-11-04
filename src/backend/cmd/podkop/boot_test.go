//go:build linux

package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// bootRouter is the dnsmasq of a router at boot: what was done to it is kept.
type bootRouter struct {
	settings string
	scripts  []string
	restarts int
}

func (r *bootRouter) ReadSettings() ([]byte, error) { return []byte(r.settings), nil }
func (r *bootRouter) Batch(script string) error     { r.scripts = append(r.scripts, script); return nil }
func (r *bootRouter) Restart() error                { r.restarts++; return nil }
func (r *bootRouter) Exists(string) bool            { return true }

type nothingHeld struct{}

func (nothingHeld) Close() error { return nil }

// Before dnsmasq starts at boot it is set to ask the backend, without a restart; not with
// dont_touch_dhcp on, not while a backend runs.
func TestBootDNS(t *testing.T) {
	directory := t.TempDir()
	settings := filepath.Join(directory, "podkop")
	free := func() (io.Closer, error) { return nothingHeld{}, nil }
	dhcp := "config dnsmasq\n\tlist server '8.8.8.8'\n\toption cachesize '1000'\n"

	require.NoError(t, os.WriteFile(settings, []byte("config settings 'settings'\n\toption dns_type 'doh'\n"), 0o644))
	router := &bootRouter{settings: dhcp}
	var output bytes.Buffer
	require.Equal(t, 0, bootDNS(&output, settings, router, free))
	require.Len(t, router.scripts, 1)
	require.Contains(t, router.scripts[0], "add_list dhcp.@dnsmasq[0].server='127.0.0.42'")
	require.Contains(t, router.scripts[0], "add_list dhcp.@dnsmasq[0].podkop_server='8.8.8.8'")
	require.Zero(t, router.restarts)
	require.Contains(t, output.String(), "dnsmasq starts asking the backend")

	require.NoError(t, os.WriteFile(settings, []byte("config settings 'settings'\n\toption dont_touch_dhcp '1'\n"), 0o644))
	router = &bootRouter{settings: dhcp}
	output.Reset()
	require.Equal(t, 0, bootDNS(&output, settings, router, free))
	require.Empty(t, router.scripts)
	require.Empty(t, output.String())

	router = &bootRouter{settings: dhcp}
	output.Reset()
	busy := func() (io.Closer, error) { return nil, errors.New("resource temporarily unavailable") }
	require.Equal(t, 0, bootDNS(&output, settings, router, busy))
	require.Empty(t, router.scripts)
	require.Contains(t, output.String(), "a backend runs")

	output.Reset()
	require.Equal(t, 1, bootDNS(&output, filepath.Join(directory, "missing"), router, free))
	require.Contains(t, output.String(), "[error]")
}
