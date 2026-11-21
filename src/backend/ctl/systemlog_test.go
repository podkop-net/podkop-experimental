package ctl

import (
	"strings"
	"testing"
)

// TestMaskSystemLog: the lines of logread with a failed login are masked, and so are the lines
// that continue one (procd cut the message at a line break of the tried password: the next
// lines of the same process at the same second); a line of another second or process is kept.
func TestMaskSystemLog(t *testing.T) {
	head := "Sat Nov 21 02:07:21 2026 daemon.err podkop[4525]: "
	lines := []string{
		head + "ERROR[0042] inbound/mixed[main-mixed-in]: process connection from 192.168.78.10:40000: socks5: authentication failed, username=pdk-user, password=Wrong",
		head + "Tail77",
		head + "AndMore",
		head + "ERROR[0042] inbound/mixed[main-mixed-in]: process connection from 192.168.78.10:40002: http: authentication failed, no Proxy-Authorization header",
		head + "[warn] a line of the backend at that second",
		head + "NotATail after a message of its own",
		"Sat Nov 21 02:07:22 2026 daemon.err podkop[4525]: ERROR[0043] a later line",
		head + "a line of the same second after an unmasked one",
		"Sat Nov 21 02:07:21 2026 daemon.info podkop[4525]: http: authentication failed, Proxy-Authorization=Basic cGRrOldyb25n",
		"Sat Nov 21 02:07:21 2026 daemon.info podkop[999]: another process at that second",
	}
	got := maskSystemLog(append([]string(nil), lines...))
	want := []string{
		head + "ERROR[0042] inbound/mixed[main-mixed-in]: process connection from 192.168.78.10:40000: socks5: authentication failed, username=MASKED",
		head + "MASKED",
		head + "MASKED",
		lines[3],
		lines[4],
		lines[5],
		lines[6],
		lines[7],
		"Sat Nov 21 02:07:21 2026 daemon.info podkop[4525]: http: authentication failed, Proxy-Authorization=MASKED",
		lines[9],
	}
	for index := range want {
		if got[index] != want[index] {
			t.Errorf("line %d:\n got %q\nwant %q", index, got[index], want[index])
		}
	}
	for _, line := range got {
		for _, secret := range []string{"Wrong", "Tail77", "AndMore", "cGRrOldyb25n", "pdk-user"} {
			if strings.Contains(line, secret) {
				t.Errorf("%q is left in %q", secret, line)
			}
		}
	}
}
