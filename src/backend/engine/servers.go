package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"time"

	"github.com/podkop-net/podkop-experimental/src/backend/detect"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
)

// serverHead is what the block detector reads of an outbound of a configuration: no field that
// holds a secret. A list of links, a subscription and a source of JSON all come to this.
type serverHead struct {
	Type       string `json:"type"`
	Tag        string `json:"tag"`
	Server     string `json:"server"`
	ServerPort uint16 `json:"server_port"`
	Detour     string `json:"detour"`
	TLS        *struct {
		Enabled    bool     `json:"enabled"`
		ServerName string   `json:"server_name"`
		ALPN       alpnList `json:"alpn"`
		UTLS       *struct {
			Enabled     bool   `json:"enabled"`
			Fingerprint string `json:"fingerprint"`
		} `json:"utls"`
		Reality *struct {
			Enabled bool `json:"enabled"`
		} `json:"reality"`
	} `json:"tls"`
	Transport *struct {
		Type     string  `json:"type"`
		Download present `json:"download"`
	} `json:"transport"`
	Multiplex *struct {
		Enabled bool `json:"enabled"`
	} `json:"multiplex"`
}

// alpnList is the ALPN of an outbound, a list or one text as the engine takes it
// (badoption.Listable, whose method is not one encoding/json calls).
type alpnList []string

func (l *alpnList) UnmarshalJSON(content []byte) error {
	var single string
	if json.Unmarshal(content, &single) == nil {
		*l = alpnList{single}
		return nil
	}
	return json.Unmarshal(content, (*[]string)(l))
}

// present tells that a field is there, and keeps nothing of it.
type present bool

func (p *present) UnmarshalJSON(content []byte) error {
	*p = string(content) != "null"
	return nil
}

// ServersOf reads the proxy servers of a configuration, in the order of its outbounds, and
// whether its uTLS fallback is on. A group, a selector, a direct outbound (an interface too) and
// the block are no servers. An outbound through a tunnel is one, of KindNone.
func ServersOf(configuration []byte) ([]detect.Server, bool) {
	var parsed struct {
		Outbounds    []json.RawMessage `json:"outbounds"`
		Experimental struct {
			UTLSFallback *struct {
				Enabled bool `json:"enabled"`
			} `json:"utls_fallback"`
		} `json:"experimental"`
	}
	if json.Unmarshal(configuration, &parsed) != nil {
		return nil, false
	}
	fallback := parsed.Experimental.UTLSFallback != nil && parsed.Experimental.UTLSFallback.Enabled
	heads := make([]serverHead, len(parsed.Outbounds))
	types := make(map[string]string, len(parsed.Outbounds))
	intervals := make(map[string]time.Duration)
	for index, content := range parsed.Outbounds {
		// an outbound of another shape is no server the detector can read
		if json.Unmarshal(content, &heads[index]) != nil {
			heads[index] = serverHead{}
			continue
		}
		types[heads[index].Tag] = heads[index].Type
		var group struct {
			Interval  badoption.Duration `json:"interval"`
			Outbounds []string           `json:"outbounds"`
			Fallbacks []string           `json:"fallbacks"`
		}
		if heads[index].Type == C.TypeURLTest && json.Unmarshal(content, &group) == nil {
			for _, member := range append(group.Outbounds, group.Fallbacks...) {
				if _, known := intervals[member]; !known {
					intervals[member] = time.Duration(group.Interval)
				}
			}
		}
	}
	var servers []detect.Server
	for index, head := range heads {
		switch head.Type {
		case "", C.TypeSelector, C.TypeURLTest, C.TypeDirect, C.TypeBlock, C.TypeDNS:
			continue
		}
		server := detect.Server{Tag: head.Tag, Hash: hashOf(parsed.Outbounds[index]), Kind: head.kind(types), Detour: head.Detour,
			TestInterval: intervals[head.Tag], Reality: head.reality(), LazyDial: head.lazyDial(), UpgradeInDial: head.upgradeInDial(),
			Framed: head.framed(), DownloadLeg: head.downloadLeg(), Content: parsed.Outbounds[index]}
		if head.Server != "" {
			server.Destination = M.ParseSocksaddrHostPort(head.Server, head.ServerPort).String()
		}
		if head.TLS != nil && head.TLS.Enabled {
			// as the engine keys what it records of the server (utlsFallback.load)
			server.ServerName = head.TLS.ServerName
			if server.ServerName == "" {
				server.ServerName = head.Server
			}
			if head.usesUTLS() {
				server.Fingerprint = head.TLS.UTLS.Fingerprint
				if server.Fingerprint == "" {
					server.Fingerprint = "chrome"
				}
			}
		}
		servers = append(servers, server)
	}
	return servers, fallback
}

// usesUTLS tells a ClientHello of a fingerprint: QUIC has its own.
func (h serverHead) usesUTLS() bool {
	if h.TLS == nil || !h.TLS.Enabled || h.TLS.UTLS == nil || h.overQUIC() {
		return false
	}
	return h.TLS.UTLS.Enabled || h.reality()
}

func (h serverHead) reality() bool {
	return h.TLS != nil && h.TLS.Enabled && h.TLS.Reality != nil && h.TLS.Reality.Enabled
}

func (h serverHead) transportIs(kinds ...string) bool {
	return h.Transport != nil && slices.Contains(kinds, h.Transport.Type)
}

// overQUIC tells a server that takes no TCP. xhttp goes by its own rule (v2rayxhttp
// decideHTTPVersion): a single ALPN of h3, unless it is REALITY.
func (h serverHead) overQUIC() bool {
	if isUDPType(h.Type) || h.transportIs(C.V2RayTransportTypeQUIC) {
		return true
	}
	return h.transportIs(C.V2RayTransportTypeXHTTP) && h.TLS != nil && h.TLS.Enabled && !h.reality() && len(h.TLS.ALPN) == 1 && h.TLS.ALPN[0] == "h3"
}

// lazyDial tells a transport whose dial returns before anything goes out: a connection of its pool
// is made for the first request.
func (h serverHead) lazyDial() bool {
	return h.transportIs(C.V2RayTransportTypeGRPC, C.V2RayTransportTypeHTTP)
}

// upgradeInDial tells a dial that ends after the upgrade to WebSocket or HTTP, over TLS.
func (h serverHead) upgradeInDial() bool {
	return h.TLS != nil && h.TLS.Enabled && h.transportIs(C.V2RayTransportTypeWebsocket, C.V2RayTransportTypeHTTPUpgrade)
}

// framed tells a transport whose frames a copy of the outbound keeps. A copy goes without multiplex
// (decodeProbeOutbound); naive and anytls have frames of their own, but no stand measured them.
func (h serverHead) framed() bool {
	return h.transportIs(C.V2RayTransportTypeGRPC, C.V2RayTransportTypeHTTP, C.V2RayTransportTypeXHTTP)
}

// downloadLeg tells xhttp with the download on a leg of its own: overQUIC reads only the main one.
func (h serverHead) downloadLeg() bool {
	return h.transportIs(C.V2RayTransportTypeXHTTP) && bool(h.Transport.Download)
}

// kind is what a probe of the outbound can do. A detour to a direct outbound is a socket to the
// server all the same (common/tls.throughTunnel); a detour of another type is a tunnel.
func (h serverHead) kind(types map[string]string) detect.Kind {
	if h.Server == "" || (h.Detour != "" && types[h.Detour] != C.TypeDirect) {
		return detect.KindNone
	}
	if h.overQUIC() {
		return detect.KindUDP
	}
	if h.Type == C.TypeNaive || h.Type == C.TypeAnyTLS || (h.Multiplex != nil && h.Multiplex.Enabled) {
		return detect.KindPooled
	}
	if h.framed() {
		return detect.KindPooled
	}
	switch {
	case h.usesUTLS():
		return detect.KindFingerprint
	case h.TLS != nil && h.TLS.Enabled:
		return detect.KindTLS
	}
	return detect.KindPlain
}

func isUDPType(kind string) bool {
	return kind == C.TypeHysteria || kind == C.TypeHysteria2 || kind == C.TypeTUIC
}

// hashOf tells one outbound from another without its content.
func hashOf(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:8])
}
