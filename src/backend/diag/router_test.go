package diag

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/podkop-net/podkop-experimental/src/backend/sockets"
	"github.com/stretchr/testify/require"
)

// The configuration dnsmasq runs with is the file of its command line and the files of its
// conf-dir lines, as the process sees them: the servers every name goes to are those
// without a domain.
func TestDnsmasqForwards(t *testing.T) {
	root := t.TempDir()
	procRoot = root
	defer func() { procRoot = "/" }()
	write := func(name string, content string) {
		path := filepath.Join(root, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	}
	write("proc/7600/cmdline", "/usr/sbin/dnsmasq\x00-C\x00/var/etc/dnsmasq.conf.cfg01411c\x00-k\x00-x\x00/var/run/dnsmasq/dnsmasq.cfg01411c.pid\x00")
	write("proc/7600/root/var/etc/dnsmasq.conf.cfg01411c", "domain-needed\nserver=127.0.0.42\nno-resolv\nserver=/lan/\nconf-dir=/tmp/dnsmasq.cfg01411c.d\n")
	write("proc/7600/root/tmp/dnsmasq.cfg01411c.d/other.conf", "server=127.0.0.1#5053\nserver=/example.org/192.0.2.1\n")
	// the file of the system has been replaced since: the process runs with the one above
	write("var/etc/dnsmasq.conf.cfg01411c", "domain-needed\nserver=/lan/\n")
	servers, noResolv, read := dnsmasqForwards(7600)
	require.True(t, read)
	require.True(t, noResolv)
	require.Equal(t, []string{"127.0.0.42", "127.0.0.1#5053"}, servers)
	_, _, read = dnsmasqForwards(7601)
	require.False(t, read)
	// a root that cannot be read: the file of the system
	write("proc/7602/cmdline", "/usr/sbin/dnsmasq\x00--conf-file=/var/etc/dnsmasq.conf.cfg01411c\x00")
	servers, noResolv, read = dnsmasqForwards(7602)
	require.True(t, read)
	require.False(t, noResolv)
	require.Empty(t, servers)
}

// A dnsmasq in a jail runs with the file of its start: stale when the file of the system
// has another content now; one outside a jail is left out.
func TestCheckDnsmasq(t *testing.T) {
	root := t.TempDir()
	procRoot = root
	defer func() { procRoot = "/" }()
	write := func(name string, content string) {
		path := filepath.Join(root, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	}
	namespace := func(pid string, target string) {
		path := filepath.Join(root, "proc", pid, "ns", "mnt")
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.Symlink(target, path))
	}
	namespace("self", "mnt:[4026531841]")
	command := "/usr/sbin/dnsmasq\x00-C\x00/var/etc/dnsmasq.conf.cfg01411c\x00-k\x00"
	written := "port=54\nserver=127.0.0.42\nno-resolv\n"
	write("var/etc/dnsmasq.conf.cfg01411c", written)
	// started with the old file
	write("proc/3706/cmdline", command)
	namespace("3706", "mnt:[4026532301]")
	write("proc/3706/root/var/etc/dnsmasq.conf.cfg01411c", "port=54\nresolv-file=/tmp/resolv.conf.d/resolv.conf.auto\n")
	// started with the file of now
	write("proc/3800/cmdline", command)
	namespace("3800", "mnt:[4026532302]")
	write("proc/3800/root/var/etc/dnsmasq.conf.cfg01411c", written)
	// outside a jail
	write("proc/3900/cmdline", command)
	namespace("3900", "mnt:[4026531841]")
	listeners := []sockets.Listener{
		{Program: "dnsmasq", PID: 3706}, {Program: "dnsmasq", PID: 3706},
		{Program: "AdGuardHome", PID: 3000},
		{Program: "dnsmasq", PID: 3800}, {Program: "dnsmasq", PID: 3900},
	}
	require.Equal(t, []DnsmasqLoaded{
		{PID: 3706, File: "/var/etc/dnsmasq.conf.cfg01411c", Stale: true, Loaded: Forwards{}, Written: Forwards{Servers: []string{"127.0.0.42"}, NoResolv: true}},
		{PID: 3800, File: "/var/etc/dnsmasq.conf.cfg01411c", Loaded: Forwards{Servers: []string{"127.0.0.42"}, NoResolv: true}, Written: Forwards{Servers: []string{"127.0.0.42"}, NoResolv: true}},
	}, CheckDnsmasq(listeners))
}
