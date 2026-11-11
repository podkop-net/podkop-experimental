// Package serverid gives an outbound its stable identity: the same destination reached the same
// way has the same id, whatever its tag, and whether or not it connects through a detour. It is
// the key a per-server cure is stored by, and the id the page joins a verdict to. One definition,
// shared by the subscription parser, the plan builder and the cure store.
package serverid

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// Canonical is hex(sha256(outbound without "tag" and "detour")[:12]) — 24 hex characters. The
// keys of the re-marshaled map are sorted by encoding/json, so the same outbound is the same
// bytes. A rename (tag) or a detour does not change it; a change of server, port, key or transport
// does. On an outbound that is not a JSON object it falls back to the hash of the bytes as given,
// so it never panics on bad input.
func Canonical(outbound []byte) string {
	var fields map[string]any
	if err := json.Unmarshal(outbound, &fields); err != nil {
		return sum(outbound)
	}
	delete(fields, "tag")
	delete(fields, "detour")
	canonical, err := json.Marshal(fields)
	if err != nil {
		return sum(outbound)
	}
	return sum(canonical)
}

func sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:12])
}
