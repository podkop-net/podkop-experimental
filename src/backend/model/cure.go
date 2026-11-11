package model

import (
	"net/netip"
	"strings"
)

// A cure is a per-server treatment of a DPI block, chosen on the dashboard and stored as a UCI
// "cure" section. It is keyed by the stable identity of the server (serverid.Canonical) and the
// source it connects through (Via, "" = direct), so the same server carries a cure on its direct
// use and not on a detoured use. Exactly one kind per server: a row holds one kind, and a new
// one replaces it.
//
//	config cure
//	    option hash 'f1e2d3c4b5a6...'   # serverid.Canonical of the server outbound, 24 hex
//	    option via  'relay'             # the through-source name; absent/'' = direct
//	    option kind 'spoof'             # spoof | record_fragment
//	    option sni  'packagist.org'     # only for kind=spoof
type Cure struct {
	Hash string
	Via  string
	Kind string
	SNI  string
}

// The kinds of a cure. spoof masks the limit with a whitelisted SNI; record_fragment beats the
// freeze while keeping the fingerprint.
const (
	CureSpoof          = "spoof"
	CureRecordFragment = "record_fragment"
)

// ValidCureKind tells a kind the store may hold.
func ValidCureKind(kind string) bool {
	return kind == CureSpoof || kind == CureRecordFragment
}

// Cure returns the cure stored for a server reached a given way, or nil. Via "" is the direct
// path. When the file holds more than one row for a {hash, via} the last wins, as a UCI reader
// takes the last of repeated options.
func (c *Config) Cure(hash, via string) *Cure {
	var found *Cure
	for index := range c.Cures {
		if c.Cures[index].Hash == hash && c.Cures[index].Via == via {
			found = &c.Cures[index]
		}
	}
	return found
}

// ValidMaskName tells a name a spoof cure may put on the wire: a lower-case DNS host name of at
// least two labels, each of letters, digits and inner hyphens, not an IP address.
func ValidMaskName(name string) bool {
	if len(name) == 0 || len(name) > 253 || strings.HasSuffix(name, ".") {
		return false
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return false
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if !(character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-') {
				return false
			}
		}
	}
	return true
}
