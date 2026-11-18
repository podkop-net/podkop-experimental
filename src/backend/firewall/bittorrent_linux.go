package firewall

import (
	"cmp"
	"encoding/json"
	"net/netip"
	"os"
	"slices"
	"time"

	"github.com/podkop-net/podkop-experimental/src/backend/dataplane"
	"github.com/sagernet/nftables"
	"github.com/sagernet/nftables/binaryutil"
	"github.com/sagernet/nftables/expr"
	"golang.org/x/sys/unix"
)

// The BitTorrent detector, design H (the workspace's notes/2026-11-16-bittorrent-architecture.md,
// approved 2026-11-16; the A5 decision record, notes/2026-11-16-a5-decision.md): the kernel decides a
// flow at its first packet from the evidence it holds, and a flow of a device running a client that
// needs more goes through sing-box, where podkop's module (package bittorrent) sees all of it,
// whatever the router offloads. Nothing guessed is stored.
//
// bt_detect, before mangle, looks at the first packet of every flow of the LAN (IPv4):
//   - UDP: a signature of a DHT message, of a connect to a UDP tracker or of a uTP SYN puts the
//     socket (the device's address and port) in bt_sockets and the device in bt_hosts; from then
//     on every flow of that socket is BitTorrent, and its far end goes to bt_peers (a uTP client
//     tries uTP to a peer first, so its TCP to it is told at the SYN). A socket that sent a uTP
//     SYN is in bt_utp. The discovery of a socket not in bt_utp (a flow whose first packet is a
//     DHT message or a tracker's connect) is marked as such: it goes through sing-box, whose
//     module learns the peers the replies name (a uTP socket learns them from its own writes, and
//     qBittorrent's DHT asks the far side to take its source port, which sing-box's would change:
//     A4 of notes/2026-11-16-bt-phaseA.md). A uTP SYN on a flow marked as discovery (its socket
//     spoke DHT to that peer before its first uTP SYN) puts the socket in bt_utp and is dropped:
//     the client tries the peer again over TCP, decided at the SYN, rather than keeping a
//     connection on a flow sing-box relays.
//   - TCP, at the SYN: to a peer the module learned for the device (bt_learned, device . peer .
//     port; the lookup refreshes it), to a tracker the device announced to (bt_trackers), or, of a
//     device running a client, to one of bt_peers on a port no other program uses (1024 and over,
//     not commonPorts), it is BitTorrent. A device running a client, to any other port no other
//     program uses, or to one of bt_peers on a port other programs use: it is inspected, in
//     sing-box. An address and a port in bt_peers are a peer's word (a reply named them and the
//     client sent a packet there, or another device shook hands with them); on port 443 the same
//     address may be a site's, and a peer list may name any address (libtorrent connects to peers
//     on any port: its no_connect_privileged_ports is off by default; El Defrawy et al., USENIX
//     SRUTI 2007, on peer lists that point a swarm at a victim's service port). So there the
//     connection's own handshake decides: TLS stays on its route, BitTorrent's (plaintext, or
//     MSE's three steps) is confirmed by the module and its far end learned for that device
//     (0.8.19; 0.8.18 took every such connection of every device running a client for BitTorrent
//     for 30 minutes: past the proxy in bypass, dropped in block). Of 18730 DHT nodes and 3773
//     peers the stand's captures of real swarms name, 7 and 1 are on such ports, none on 443, and
//     none of 14853 BitTorrent TCP connections went to one (lab/bt17/uports.py).
//   - TCP, the first data: the plaintext handshake, or an announce to an HTTP tracker (which tells
//     the device runs a client, and puts the tracker, on a port no other program uses, in
//     bt_trackers for the device, for trackerTimeout: its next announces are BitTorrent at their
//     SYN, the mode's way, as UDP trackers are; 0.8.18, after the field's reports, where announces
//     to trackers of the user's lists went through the rule's server in bypass. A set of its own
//     since 0.8.19: in bt_peers the tracker lost its two hours to any other packet to it, and its
//     SYN was told only while the device was in bt_hosts, 30 minutes, less than the interval of an
//     announce: a client that only seeds announced through the rule's server every time).
//   - Nothing to an address of the router itself (fib daddr type local): a client that connects to
//     the router's own WAN address (its external address learned by UPnP) is no peer (0.8.18).
//
// The decision is kept in the conntrack mark of the connection: a connection never changes its
// way on the run. bt_act, after mangle, does what the mode says with it:
//   - of the traffic podkop takes (mangle marked it for the proxy): bypass lets it past podkop
//     (forwarded, the router may offload it), but sends the discovery to sing-box's BitTorrent
//     inbound (out directly, the peers learned); block drops it; section sends it to the
//     BitTorrent inbound, whose route rule sends it to the servers of the rule. An inspected
//     connection goes to the inspection inbound, where sing-box routes it as podkop's rules say
//     (the tentative route (ii) of the owner's choice of 2026-11-16) and the module confirms or
//     refutes it: confirmed, it is closed in block; in bypass and section its far end is learned
//     and it is closed, so that the device's retry is decided at its SYN (the owner's choice of
//     2026-11-17).
//   - of the traffic podkop does not take: its discovery goes to the inbound of the LAN (out
//     directly, the peers learned), but in the section for the whole LAN everything told goes to
//     the BitTorrent inbound. With the scope of the whole LAN (LAN), an inspected connection goes
//     to the inbound of the LAN: out directly, closed in block once confirmed, its far end learned
//     and the connection closed in section. The block of the whole LAN drops in bt_decided what is
//     told, for every device.
// In block, a new connection from outside (a port forward) to a client's socket is dropped too;
// in bypass and section, such a connection goes on as forwarded (sing-box cannot take it).
//
// A change of the mode: a connection decided before goes on by its mark, and the new mode takes
// its next packet. The sets go into the table made anew (bitTorrentKept), and a decided connection
// puts its device, socket and peer back in them when they are not there (a table of a start has
// none). A connection the router offloads passes no rule at all: when the new mode ends a way the
// old one gave the connections of BitTorrent past podkop (ForgetFor), the backend ends their
// conntrack entries (ForgetBitTorrentFlows), and the next packet of such a connection makes a new
// entry that the sets tell (a TCP packet whose SYN was not seen, to a peer the device knows, is
// taken as a plaintext handshake is).

// BitTorrent is what the firewall does with the traffic of BitTorrent clients it tells.
type BitTorrent struct {
	// Mode is "" (off), BitTorrentBypass, BitTorrentBlock or BitTorrentSection.
	Mode string
	// LAN is the scope of the whole LAN, for block and section: every device of the interfaces,
	// not only what the backend takes.
	LAN bool
	// Sources are the devices the backend routes whole: in block (not LAN), a new connection from
	// outside to a client's socket on one of them is dropped.
	Sources []netip.Prefix
}

const (
	BitTorrentBypass  = "bypass"
	BitTorrentBlock   = "block"
	BitTorrentSection = "section"
)

const (
	SetBitTorrentSockets = "bt_sockets"
	SetBitTorrentHosts   = dataplane.BitTorrentHostsSet
	SetBitTorrentPeers   = "bt_peers"
	SetBitTorrentUTP     = "bt_utp"
	// SetBitTorrentLearned is the set podkop's module writes (package bittorrent): device . peer .
	// port.
	SetBitTorrentLearned = dataplane.BitTorrentLearnedSet
	// SetBitTorrentTrackers are the HTTP trackers a device announced to: device . tracker . port.
	SetBitTorrentTrackers = "bt_trackers"
)

// The chains of the detector whose rules' counters BitTorrentDrops reads.
const (
	ChainBitTorrentBlock    = "bt_block"
	ChainBitTorrentIncoming = "bt_incoming"
	ChainBitTorrentDecided  = "bt_decided"
)

// bitTorrentTimeout is how long a socket, a device and a peer are kept after their last packet of
// BitTorrent: the prototype's value, with which all four clients of the stand were told whole.
const bitTorrentTimeout = 30 * time.Minute

// trackerTimeout is how long an HTTP tracker stays in bt_trackers after a connection of its device
// to it: longer than the interval trackers ask between announces (asked on 2026-11-17: opentrackr
// 3476 s, its minimum 1738 s; Ubuntu's tracker 1800 s), so that the next one finds it.
const trackerTimeout = 2 * time.Hour

// firstFreePort: a peer of bt_peers on a port under it is not taken at its word (the module's
// learnable has the same bound): of the stand's 14853 BitTorrent TCP connections, 21 went to a
// port under 1024, with no data (lab/bt17/uports.py).
const firstFreePort = 1024

// The priorities of the chains of the detector: before mangle (filter, -150) and after it, both
// before proxy (-100); bt_incoming before fw4's forward chain (filter, 0).
const (
	bitTorrentDetectPriority   = -160
	bitTorrentActPriority      = -149
	bitTorrentIncomingPriority = -1
)

const (
	ctBitTorrent  = dataplane.BitTorrentCt
	ctLate        = dataplane.BitTorrentLateCt
	ctNot         = dataplane.BitTorrentNotCt
	ctInspect     = dataplane.BitTorrentInspectCt
	ctDiscovery   = dataplane.BitTorrentDiscoveryCt
	ctIntercepted = dataplane.InterceptedCt
	ctDecided     = ctBitTorrent | ctLate | ctNot | ctInspect
)

// lsdAddress is the multicast group of the local peer discovery of BitTorrent (BEP 14), port 6771.
var lsdAddress = []byte{239, 192, 152, 143}

// commonPorts: the TCP of a device running a client to any other port is inspected
// (dataplane.BitTorrentCommonPorts).
var commonPorts = dataplane.BitTorrentCommonPorts

// the signatures of the first packet of a UDP socket of a client: a query, a response, a
// response with the address of the asker and an error of DHT (bencoded KRPC, BEP 5; libtorrent's
// queries to the bootstrap nodes begin "d1:ad2:bs", so the prefix stops before "id"), the connect
// of the UDP tracker (BEP 15: the protocol id and the action 0)
var (
	signatureDHTQuery    = []byte("d1:ad2:")
	signatureDHTResponse = []byte("d1:rd2:")
	signatureDHTAddress  = []byte("d2:ip6:")
	signatureDHTError    = []byte("d1:eli")
	signatureTracker     = []byte{0, 0, 0x04, 0x17, 0x27, 0x10, 0x19, 0x80, 0, 0, 0, 0}
	// the plaintext handshake of TCP: the length 19 and "BitTorrent protocol"
	signatureHandshake = append([]byte{19}, "BitTorrent protocol"...)
	// the announce of a client to an HTTP tracker (BEP 3): a client that speaks only encrypted TCP to
	// its peers and asks such a tracker for them (rTorrent of a public swarm of Debian, whose tracker
	// is HTTP, 2026-11-15) sends no UDP the detector knows, and is told by this. The query follows
	// the path at once (an announce carries info_hash), at /announce or /announce.php: a page such
	// as /announcements is none
	signatureAnnounce    = []byte("GET /announce?")
	signatureAnnouncePHP = []byte("GET /announce.php?")
)

// inner loads length bytes of the payload of a packet, after its transport header, from offset.
func inner(offset uint32, length uint32) expr.Any {
	return &expr.Payload{DestRegister: 1, Base: expr.PayloadBase(unix.NFT_PAYLOAD_INNER_HEADER), Offset: offset, Len: length}
}

func innerIs(offset uint32, data []byte) []expr.Any {
	return []expr.Any{inner(offset, uint32(len(data))), &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: data}}
}

// hasPayload matches a packet that carries data after its transport header.
func hasPayload() []expr.Any {
	return []expr.Any{inner(0, 1), &expr.Range{Op: expr.CmpOpEq, Register: 1, FromData: []byte{0}, ToData: []byte{0xff}}}
}

// ctMarkTest compares the bits of the conntrack mark with nothing: op Neq, some of them are set.
func ctMarkTest(bits uint32, op expr.CmpOp) []expr.Any {
	return []expr.Any{
		&expr.Ct{Key: expr.CtKeyMARK, Register: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: binaryutil.NativeEndian.PutUint32(bits), Xor: binaryutil.NativeEndian.PutUint32(0)},
		&expr.Cmp{Op: op, Register: 1, Data: binaryutil.NativeEndian.PutUint32(0)},
	}
}

// ctMarkAdd sets the bits in the conntrack mark, keeping the others (mwan3's among them).
func ctMarkAdd(bits uint32) []expr.Any {
	return []expr.Any{
		&expr.Ct{Key: expr.CtKeyMARK, Register: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: binaryutil.NativeEndian.PutUint32(^bits), Xor: binaryutil.NativeEndian.PutUint32(bits)},
		&expr.Ct{Key: expr.CtKeyMARK, Register: 1, SourceRegister: true},
	}
}

// endpoint loads an address and a port of a packet, for a key of address . port: the source
// (offsetSource, port at 0) or the destination (offsetDestination, port at 2).
func endpoint(addressOffset uint32, portOffset uint32) []expr.Any {
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: addressOffset, Len: 4},
		&expr.Payload{DestRegister: 9, Base: expr.PayloadBaseTransportHeader, Offset: portOffset, Len: 2},
	}
}

func inSet(set *nftables.Set) expr.Any {
	return &expr.Lookup{SourceRegister: 1, SetName: set.Name, SetID: set.ID}
}

func update(set *nftables.Set) expr.Any {
	return &expr.Dynset{SrcRegKey: 1, SetName: set.Name, SetID: set.ID, Operation: unix.NFT_DYNSET_OP_UPDATE}
}

func verdict(kind expr.VerdictKind, chain string) []expr.Any {
	return []expr.Any{&expr.Verdict{Kind: kind, Chain: chain}}
}

// bitTorrentSetNames are the sets of the detector whose elements a table made anew keeps, in the
// order they are kept when not all can be (keepBitTorrent).
var bitTorrentSetNames = []string{SetBitTorrentHosts, SetBitTorrentSockets, SetBitTorrentUTP, SetBitTorrentTrackers, SetBitTorrentLearned, SetBitTorrentPeers}

// bitTorrentKeys is the length of a key of each set of the detector, and bitTorrentTimeouts the
// longest an element of it has left: what is kept of a set is checked against them (a file of
// another version, or one changed, must not give the kernel a key of another length).
var (
	bitTorrentKeys = map[string]int{SetBitTorrentHosts: 4, SetBitTorrentSockets: 8, SetBitTorrentUTP: 8, SetBitTorrentPeers: 8,
		SetBitTorrentLearned: 12, SetBitTorrentTrackers: 12}
	bitTorrentTimeouts = map[string]time.Duration{SetBitTorrentTrackers: trackerTimeout}
)

// bitTorrentKeptMost is the most elements kept of each set, those with the most time left (the
// last used): the kept elements go into the transaction that makes the table, and a transaction
// of a hundred thousand elements took a router with 128 MB to the OOM killer (fillLot). Together
// they are fillLot at most. The stand's sets held at most 1464 peers and 785 learned peers at the
// end of a run of one client (lab/bt17/sizes.py); the ones left out are learned again from the
// next replies and handshakes.
var bitTorrentKeptMost = map[string]int{SetBitTorrentHosts: 500, SetBitTorrentSockets: 500, SetBitTorrentUTP: 500, SetBitTorrentTrackers: 500,
	SetBitTorrentLearned: 4000, SetBitTorrentPeers: 4000}

// keepBitTorrent leaves of the elements read of the sets (or of a file) what a new table takes:
// the sets of the detector only, keys of their length, a time left of a second to the set's
// timeout, and at most bitTorrentKeptMost of each, those with the most time left.
func keepBitTorrent(kept map[string][]nftables.SetElement) map[string][]nftables.SetElement {
	checked := make(map[string][]nftables.SetElement)
	for _, name := range bitTorrentSetNames {
		longest := bitTorrentTimeout
		if timeout, has := bitTorrentTimeouts[name]; has {
			longest = timeout
		}
		var elements []nftables.SetElement
		for _, element := range kept[name] {
			if len(element.Key) != bitTorrentKeys[name] || element.Timeout < time.Second {
				continue
			}
			elements = append(elements, nftables.SetElement{Key: element.Key, Timeout: min(element.Timeout, longest)})
		}
		if most := bitTorrentKeptMost[name]; len(elements) > most {
			slices.SortStableFunc(elements, func(a, b nftables.SetElement) int { return cmp.Compare(b.Timeout, a.Timeout) })
			elements = elements[:most]
		}
		if len(elements) > 0 {
			checked[name] = elements
		}
	}
	return checked
}

// bitTorrentKept reads what the sets of the detector of the table there now hold, each element
// with the time it has left: a table made anew while the backend runs (a change of the settings
// that changes its rules) starts with them. Without them, a connection whose conntrack entry
// ForgetBitTorrentFlows ended would make a new entry the detector cannot tell: the next packet of
// a uTP connection carries no signature, and only its socket in bt_sockets says what it is. A
// table, or a set, that is not there gives nothing.
func bitTorrentKept() map[string][]nftables.SetElement {
	conn, err := newConn()
	if err != nil {
		return nil
	}
	table := &nftables.Table{Name: tableName, Family: nftables.TableFamilyINet}
	kept := make(map[string][]nftables.SetElement)
	for _, name := range bitTorrentSetNames {
		set, err := conn.GetSetByName(table, name)
		if err != nil {
			continue
		}
		elements, err := conn.GetSetElements(set)
		if err != nil {
			continue
		}
		for _, element := range elements {
			// an element about to go is not worth a new timer
			if element.Expires >= time.Second {
				kept[name] = append(kept[name], nftables.SetElement{Key: element.Key, Timeout: element.Expires})
			}
		}
	}
	return keepBitTorrent(kept)
}

// bitTorrentSaved is where Remove keeps what the sets of the detector hold, with the time each
// element has left, and Apply takes it when there is no table to read them from: a restart of
// podkop (its stop removes the table) keeps the devices, sockets and peers it knew. In RAM: a reboot
// starts from nothing, as the clients do (0.8.18, after the field's reports: testers restart podkop
// to start the statistics again, and a client's first connections after it went by the lists).
var bitTorrentSaved = "/var/run/podkop-bittorrent-sets.json"

type savedSets struct {
	Saved time.Time                 `json:"saved"`
	Sets  map[string][]savedElement `json:"sets"`
}

type savedElement struct {
	Key  []byte        `json:"key"`
	Left time.Duration `json:"left"`
}

// saveBitTorrentSets writes what the sets of the table there now hold to bitTorrentSaved; with
// sets that hold nothing, a file of an earlier stop goes and none is written. With no table, the
// file is left as it is: a stop removes the table twice (the backend, then `podkop release` of
// the init script), and the second must not take what the first saved. An empty bitTorrentSaved
// (the firewall's tests) saves nothing.
func saveBitTorrentSets(now time.Time) {
	if bitTorrentSaved == "" || !bitTorrentSetsThere() {
		return
	}
	kept := bitTorrentKept()
	saved := savedSets{Saved: now, Sets: make(map[string][]savedElement)}
	for name, elements := range kept {
		for _, element := range elements {
			saved.Sets[name] = append(saved.Sets[name], savedElement{Key: element.Key, Left: element.Timeout})
		}
	}
	if len(saved.Sets) == 0 {
		_ = os.Remove(bitTorrentSaved)
		return
	}
	data, err := json.Marshal(saved)
	if err == nil {
		_ = os.WriteFile(bitTorrentSaved, data, 0o600)
	}
}

// loadBitTorrentSets takes the file of saveBitTorrentSets (and removes it): each element with the
// time it had left less the time since it was saved; an element that ran out is left out, and a
// file from the future (the clock went back) gives nothing.
func loadBitTorrentSets(now time.Time) map[string][]nftables.SetElement {
	if bitTorrentSaved == "" {
		return nil
	}
	data, err := os.ReadFile(bitTorrentSaved)
	if err != nil {
		return nil
	}
	_ = os.Remove(bitTorrentSaved)
	var saved savedSets
	if json.Unmarshal(data, &saved) != nil {
		return nil
	}
	elapsed := now.Sub(saved.Saved)
	if elapsed < 0 {
		return nil
	}
	kept := make(map[string][]nftables.SetElement)
	for name, elements := range saved.Sets {
		for _, element := range elements {
			if left := element.Left - elapsed; left >= time.Second {
				kept[name] = append(kept[name], nftables.SetElement{Key: element.Key, Timeout: left})
			}
		}
	}
	return keepBitTorrent(kept)
}

// bitTorrentSetsThere tells whether the table there now has the detector's set of devices.
func bitTorrentSetsThere() bool {
	conn, err := newConn()
	if err != nil {
		return false
	}
	_, err = conn.GetSetByName(&nftables.Table{Name: tableName, Family: nftables.TableFamilyINet}, SetBitTorrentHosts)
	return err == nil
}

// bitTorrentSets are the sets of the detector.
type bitTorrentSets struct {
	sockets, hosts, peers, utp, learned, trackers *nftables.Set
}

// addBitTorrentSets adds the sets of the detector, with the elements kept of the table before:
// by addElements, a message at a time, as the sets of the lists (a set holds up to 65535, and the
// elements of one message go in one attribute of at most 64 KiB, which takes about two thousand of
// bt_peers).
func addBitTorrentSets(conn *nftables.Conn, table *nftables.Table, nextID *uint32, kept map[string][]nftables.SetElement) (sets bitTorrentSets, err error) {
	endpointType := nftables.MustConcatSetType(nftables.TypeIPAddr, nftables.TypeInetService)
	devicePeerType := nftables.MustConcatSetType(nftables.TypeIPAddr, nftables.TypeIPAddr, nftables.TypeInetService)
	newSet := func(name string, keyType nftables.SetDatatype, concatenation bool, timeout time.Duration) (*nftables.Set, error) {
		if err != nil {
			return nil, err
		}
		*nextID++
		set := &nftables.Set{Table: table, ID: *nextID, Name: name, KeyType: keyType, Dynamic: true, HasTimeout: true,
			Timeout: timeout, Concatenation: concatenation}
		if err := conn.AddSet(set, nil); err != nil {
			return set, err
		}
		return set, addElements(conn, set, kept[name])
	}
	sets.sockets, err = newSet(SetBitTorrentSockets, endpointType, true, bitTorrentTimeout)
	sets.hosts, err = newSet(SetBitTorrentHosts, nftables.TypeIPAddr, false, bitTorrentTimeout)
	sets.peers, err = newSet(SetBitTorrentPeers, endpointType, true, bitTorrentTimeout)
	sets.utp, err = newSet(SetBitTorrentUTP, endpointType, true, bitTorrentTimeout)
	sets.learned, err = newSet(SetBitTorrentLearned, devicePeerType, true, bitTorrentTimeout)
	sets.trackers, err = newSet(SetBitTorrentTrackers, devicePeerType, true, trackerTimeout)
	return
}

// tproxyTo sends a packet to the transparent proxy inbound on port, and accepts it there: tproxy
// does not end the rules of a chain, and the rule of the transparent proxy after it would take the
// packet again (on the stand of 2026-11-15 every packet of the inbound of BitTorrent was counted by
// both).
func tproxyTo(port uint16) []expr.Any {
	return []expr.Any{
		&expr.Immediate{Register: 1, Data: addressProxy.AsSlice()},
		&expr.Immediate{Register: 2, Data: binaryutil.BigEndian.PutUint16(port)},
		&expr.TProxy{Family: byte(nftables.TableFamilyIPv4), TableFamily: byte(nftables.TableFamilyINet), RegAddr: 1, RegPort: 2},
		&expr.Counter{},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}
}

func markedForProxy() []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: binaryutil.NativeEndian.PutUint32(markProxy), Xor: binaryutil.NativeEndian.PutUint32(0)},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(markProxy)},
	}
}

// addBitTorrentProxy adds the first rules of proxy: what bt_act left marked for the proxy goes to
// an inbound of BitTorrent by its conntrack mark, before the rule of the transparent proxy.
//   - inspected, of the traffic podkop takes: the inspection inbound (its rules are podkop's);
//   - inspected, of the traffic podkop does not take (the scope of the whole LAN): the inbound of
//     the LAN;
//   - told as BitTorrent, of the traffic podkop takes (bypass: the discovery, the rest went past
//     podkop; section: all): the BitTorrent inbound;
//   - told as BitTorrent, of the traffic podkop does not take (bt_act marked it): the BitTorrent
//     inbound in the section for the whole LAN, the inbound of the LAN otherwise (the discovery).
func addBitTorrentProxy(add func(*nftables.Chain, ...[]expr.Any), proxy *nftables.Chain, detector BitTorrent) {
	type route struct {
		bits        uint32
		intercepted bool
		port        uint16
	}
	routes := []route{{ctInspect, true, dataplane.BitTorrentCheckTProxyPort}}
	if detector.LAN {
		routes = append(routes, route{ctInspect, false, dataplane.BitTorrentLANTProxyPort})
	}
	if detector.Mode != BitTorrentBlock {
		freePort := uint16(dataplane.BitTorrentLANTProxyPort)
		if detector.Mode == BitTorrentSection && detector.LAN {
			freePort = dataplane.BitTorrentTProxyPort
		}
		routes = append(routes, route{ctBitTorrent, true, dataplane.BitTorrentTProxyPort}, route{ctBitTorrent, false, freePort})
	}
	for _, r := range routes {
		intercepted := ctMarkTest(ctIntercepted, expr.CmpOpNeq)
		if !r.intercepted {
			intercepted = ctMarkTest(ctIntercepted, expr.CmpOpEq)
		}
		for _, transport := range []byte{unix.IPPROTO_TCP, unix.IPPROTO_UDP} {
			add(proxy, ctMarkTest(r.bits, expr.CmpOpNeq), intercepted, markedForProxy(), protocol(transport), tproxyTo(r.port))
		}
	}
}

// addBitTorrent adds the sets (with what kept holds of them) and the chains of the detector to
// the table.
func addBitTorrent(conn *nftables.Conn, table *nftables.Table, plan *Plan, add func(*nftables.Chain, ...[]expr.Any), nextID *uint32,
	kept map[string][]nftables.SetElement) error {
	detector := plan.BitTorrent
	mode := detector.Mode
	sets, err := addBitTorrentSets(conn, table, nextID, kept)
	if err != nil {
		return err
	}
	sockets, hosts, peers, utp, learned, trackers := sets.sockets, sets.hosts, sets.peers, sets.utp, sets.learned, sets.trackers
	var elements []nftables.SetElement
	for _, port := range commonPorts {
		elements = append(elements, nftables.SetElement{Key: binaryutil.BigEndian.PutUint16(port)})
	}
	// notCommonPort: the port at offset is none of commonPorts, by an anonymous set of its own for
	// each rule: the kernel binds an anonymous set to the one rule it is in, and answers the rule
	// of a second with EBUSY
	var portsErr error
	notCommonPort := func(offset uint32) []expr.Any {
		*nextID++
		ports := &nftables.Set{Table: table, ID: *nextID, Name: "__set%d", Anonymous: true, Constant: true, KeyType: nftables.TypeInetService}
		if err := conn.AddSet(ports, elements); err != nil && portsErr == nil {
			portsErr = err
		}
		return []expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: offset, Len: 2},
			&expr.Lookup{SourceRegister: 1, SetName: ports.Name, SetID: ports.ID, Invert: true},
		}
	}
	accept := nftables.ChainPolicyAccept
	detect := conn.AddChain(&nftables.Chain{Name: "bt_detect", Table: table, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookPrerouting, Priority: nftables.ChainPriorityRef(bitTorrentDetectPriority), Policy: &accept})
	chain := func(name string) *nftables.Chain {
		return conn.AddChain(&nftables.Chain{Name: name, Table: table})
	}
	udp, discovery, socket, flow := chain("bt_udp"), chain("bt_discovery"), chain("bt_socket"), chain("bt_flow")
	tcp, syn, handshake, decided := chain("bt_tcp"), chain("bt_syn"), chain("bt_handshake"), chain(ChainBitTorrentDecided)
	act := conn.AddChain(&nftables.Chain{Name: "bt_act", Table: table, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookPrerouting, Priority: nftables.ChainPriorityRef(bitTorrentActPriority), Policy: &accept})
	free := chain("bt_free")
	// bt_block: what the mode block drops, counted by its kind (the dashboard's table of
	// BitTorrent: a connection blocked at its first packet makes no conntrack entry to count)
	var block *nftables.Chain
	if mode == BitTorrentBlock {
		block = chain(ChainBitTorrentBlock)
	}
	returns := verdict(expr.VerdictReturn, "")
	counter := []expr.Any{&expr.Counter{}}

	// every rule that reads an address or a port says what it reads first, as nft does: the
	// listing then reads as the rules were written
	tcp4 := func() []expr.Any { return append(ipv4(), protocol(unix.IPPROTO_TCP)...) }
	udp4 := func() []expr.Any { return append(ipv4(), protocol(unix.IPPROTO_UDP)...) }
	updateHost := func() [][]expr.Any { return [][]expr.Any{ipv4(), {addressLoad(offsetSource), update(hosts)}} }
	// the device, the peer and its port of a TCP packet, for bt_learned and bt_trackers
	devicePeerKey := func() []expr.Any {
		return []expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offsetSource, Len: 4},
			&expr.Payload{DestRegister: 9, Base: expr.PayloadBaseNetworkHeader, Offset: offsetDestination, Len: 4},
			&expr.Payload{DestRegister: 10, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		}
	}
	devicePeer := func() []expr.Any { return append(tcp4(), devicePeerKey()...) }
	// freePort: the destination port of a TCP packet is firstFreePort or over and none of
	// commonPorts
	freePort := func() [][]expr.Any {
		return [][]expr.Any{protocol(unix.IPPROTO_TCP), {
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
			&expr.Cmp{Op: expr.CmpOpGte, Register: 1, Data: binaryutil.BigEndian.PutUint16(firstFreePort)},
		}, notCommonPort(2)}
	}
	setMark := func(on bool) []expr.Any {
		mask, xor := ^uint32(markProxy), uint32(0)
		if on {
			mask, xor = ^uint32(markProxy), markProxy
		}
		return []expr.Any{
			&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: binaryutil.NativeEndian.PutUint32(mask), Xor: binaryutil.NativeEndian.PutUint32(xor)},
			&expr.Meta{Key: expr.MetaKeyMARK, SourceRegister: true, Register: 1},
		}
	}

	// bt_detect: what comes from the LAN, IPv4; a connection decided before goes by its mark
	add(detect, []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Lookup{SourceRegister: 1, SetName: SetInterfaces, SetID: idInterfaces, Invert: true},
	}, returns)
	add(detect, []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{unix.NFPROTO_IPV4}},
	}, returns)
	// an address of the router itself (its WAN address, which a client may know by UPnP)
	add(detect, []expr.Any{
		&expr.Fib{Register: 1, FlagDADDR: true, ResultADDRTYPE: true},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(unix.RTN_LOCAL)},
	}, returns)
	add(detect, ctMarkTest(ctDecided, expr.CmpOpNeq), verdict(expr.VerdictGoto, decided.Name))
	add(detect, protocol(unix.IPPROTO_UDP), verdict(expr.VerdictGoto, udp.Name))
	add(detect, protocol(unix.IPPROTO_TCP), verdict(expr.VerdictGoto, tcp.Name))

	// bt_udp: the first packet of a flow; the signatures before a known socket, so that a known
	// socket's uTP SYN puts it in bt_utp and its discovery is marked
	add(udp, ipv4(), []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offsetDestination, Len: 4},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: lsdAddress},
	}, protocol(unix.IPPROTO_UDP), destinationPort(6771), []expr.Any{addressLoad(offsetSource), update(hosts), &expr.Counter{}}, returns)
	add(udp, ipv4(), addressIn(offsetDestination, SetLocal, idLocal), returns)
	// a uTP SYN of version 1 (BEP 29), as the clients send it: the header of 20 bytes alone with no
	// extension, or with the one extension of 8 bytes (type 2) older uTorrent sent; a timestamp
	// difference and an ack_nr of 0. Every one of the 53798 SYNs of the stand's captures
	// (qBittorrent, Transmission, M4's clients; lab/bt17/uports.py) is the first. 0.8.18 took any
	// packet that begins 0x41 with a byte under 3 and four zeros at 8: 3 of 65536 DNS queries
	// without EDNS (the id, then NSCOUNT and ARCOUNT) among others, whose flow, socket and device
	// became BitTorrent.
	udpLength := func(length uint16) []expr.Any {
		return []expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 4, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(8 + length)},
		}
	}
	utpSyns := [][][]expr.Any{
		{protocol(unix.IPPROTO_UDP), udpLength(20), innerIs(0, []byte{0x41, 0}), innerIs(8, []byte{0, 0, 0, 0}), innerIs(18, []byte{0, 0})},
		{protocol(unix.IPPROTO_UDP), udpLength(30), innerIs(0, []byte{0x41, 2}), innerIs(8, []byte{0, 0, 0, 0}), innerIs(18, []byte{0, 0, 0, 8})},
	}
	for _, utpSyn := range utpSyns {
		add(udp, append(append([][]expr.Any{}, utpSyn...), udp4(), endpoint(offsetSource, 0), []expr.Any{update(utp)}, counter, verdict(expr.VerdictGoto, socket.Name))...)
	}
	for _, signature := range [][]byte{signatureDHTQuery, signatureDHTResponse, signatureDHTAddress, signatureDHTError, signatureTracker} {
		add(udp, innerIs(0, signature), counter, verdict(expr.VerdictGoto, discovery.Name))
	}
	add(udp, udp4(), endpoint(offsetSource, 0), []expr.Any{inSet(sockets)}, verdict(expr.VerdictGoto, flow.Name))
	add(udp, ctMarkAdd(ctNot))

	// bt_discovery: a DHT message or a tracker's connect; of a socket not in bt_utp, discovery
	add(discovery, udp4(), endpoint(offsetSource, 0), []expr.Any{update(sockets)})
	add(discovery, updateHost()...)
	add(discovery, udp4(), endpoint(offsetSource, 0), []expr.Any{inSet(utp)}, verdict(expr.VerdictGoto, flow.Name))
	add(discovery, ctMarkAdd(ctDiscovery), counter, verdict(expr.VerdictGoto, flow.Name))

	// bt_socket: a socket of a client, and its device
	add(socket, udp4(), endpoint(offsetSource, 0), []expr.Any{update(sockets)})
	add(socket, updateHost()...)
	add(socket, verdict(expr.VerdictGoto, flow.Name))

	// bt_flow: a flow of a socket of a client, and its peer
	add(flow, udp4(), endpoint(offsetDestination, 2), []expr.Any{update(peers)})
	add(flow, ctMarkAdd(ctBitTorrent), counter)
	add(flow, verdict(expr.VerdictGoto, decided.Name))

	// bt_tcp: the SYN and the first data of a connection
	add(tcp, ipv4(), addressIn(offsetDestination, SetLocal, idLocal), returns)
	add(tcp, protocol(unix.IPPROTO_TCP), []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 13, Len: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 1, Mask: []byte{0x12}, Xor: []byte{0}},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x02}},
	}, verdict(expr.VerdictGoto, syn.Name))
	add(tcp, innerIs(0, signatureHandshake[:12]), innerIs(12, signatureHandshake[12:20]), counter, verdict(expr.VerdictGoto, handshake.Name))
	// an announce to an HTTP tracker: the device runs a client; the connection itself is the
	// tracker's, not of the swarm. The tracker, on an uncommon port, is BitTorrent for the device
	// from its next connection on (bt_trackers, for trackerTimeout)
	for _, signature := range [][][]expr.Any{
		{innerIs(0, signatureAnnounce)},
		{innerIs(0, signatureAnnouncePHP[:12]), innerIs(12, signatureAnnouncePHP[12:])},
	} {
		// in the order nft writes "tcp dport != {...} update @bt_trackers { ip saddr . ip daddr . tcp dport }"
		tracker := append(append([][]expr.Any{}, signature...), protocol(unix.IPPROTO_TCP), notCommonPort(2), ipv4(), devicePeerKey(),
			[]expr.Any{update(trackers)})
		add(tcp, tracker...)
		announce := append(append([][]expr.Any{}, signature...), updateHost()...)
		add(tcp, append(announce, ctMarkAdd(ctNot), counter, returns)...)
	}
	// a packet of a connection whose SYN this table did not see, or saw before its peer was known
	// (the entry of a connection ForgetBitTorrentFlows ended makes a new one with its next packet):
	// a device running a client, to a peer it knows, is taken as a plaintext handshake is
	add(tcp, devicePeer(), []expr.Any{&expr.Lookup{SourceRegister: 1, SetName: learned.Name, SetID: learned.ID}}, counter, verdict(expr.VerdictGoto, handshake.Name))
	// (a peer of bt_peers on a port other programs use is not taken at its word: the top)
	add(tcp, append(append([][]expr.Any{ipv4(), addressIn(offsetSource, SetBitTorrentHosts, hosts.ID)}, freePort()...), endpoint(offsetDestination, 2),
		[]expr.Any{inSet(peers)}, counter, verdict(expr.VerdictGoto, handshake.Name))...)
	add(tcp, hasPayload(), ctMarkAdd(ctNot))

	// bt_syn: a connection to a peer the module learned for the device (refreshed: an element
	// added again from userspace keeps its timer on kernel 6.6, R7 of the A5 review), to a tracker
	// the device announced to (refreshed; the device runs a client), or, of a device running a
	// client, to a peer of bt_peers on a port no other program uses: BitTorrent. Else, of a device
	// running a client: to a peer of bt_peers on any other port, or to any uncommon port, inspected
	add(syn, devicePeer(), []expr.Any{&expr.Lookup{SourceRegister: 1, SetName: learned.Name, SetID: learned.ID}},
		devicePeer(), []expr.Any{&expr.Dynset{SrcRegKey: 1, SetName: learned.Name, SetID: learned.ID, Operation: unix.NFT_DYNSET_OP_UPDATE}},
		ctMarkAdd(ctBitTorrent), counter, verdict(expr.VerdictGoto, decided.Name))
	add(syn, append([][]expr.Any{devicePeer(), {&expr.Lookup{SourceRegister: 1, SetName: trackers.Name, SetID: trackers.ID}},
		devicePeer(), {update(trackers)}}, append(updateHost(), ctMarkAdd(ctBitTorrent), counter, verdict(expr.VerdictGoto, decided.Name))...)...)
	add(syn, append(append([][]expr.Any{ipv4(), addressIn(offsetSource, SetBitTorrentHosts, hosts.ID)}, freePort()...), endpoint(offsetDestination, 2),
		[]expr.Any{inSet(peers)}, ctMarkAdd(ctBitTorrent), counter, verdict(expr.VerdictGoto, decided.Name))...)
	add(syn, ipv4(), addressIn(offsetSource, SetBitTorrentHosts, hosts.ID), protocol(unix.IPPROTO_TCP), endpoint(offsetDestination, 2),
		[]expr.Any{inSet(peers)}, ctMarkAdd(ctInspect), counter, returns)
	add(syn, ipv4(), addressIn(offsetSource, SetBitTorrentHosts, hosts.ID), protocol(unix.IPPROTO_TCP), notCommonPort(2),
		ctMarkAdd(ctInspect), counter, returns)

	// bt_handshake: the plaintext handshake; a connection the proxy has taken stays with sing-box
	add(handshake, updateHost()...)
	add(handshake, tcp4(), endpoint(offsetDestination, 2), []expr.Any{update(peers)})
	add(handshake, ctMarkTest(ctIntercepted, expr.CmpOpNeq), ctMarkAdd(ctLate), counter, returns)
	add(handshake, ctMarkAdd(ctBitTorrent), counter, verdict(expr.VerdictGoto, decided.Name))

	// bt_decided: a connection of BitTorrent, for every device with the block of the whole LAN.
	// While it lasts, its device, its socket and its peer are put back in the sets when they are
	// not there: a table made when the backend started has none, and a device whose connections
	// were decided before (their marks are in conntrack) is told again at their next packets, its
	// new connections with it (on the stand of 2026-11-15, a restart of podkop in the mode block let
	// the encrypted retry of a blocked connection through: the device was in no set)
	notIn := func(set *nftables.Set) []expr.Any {
		return []expr.Any{&expr.Lookup{SourceRegister: 1, SetName: set.Name, SetID: set.ID, Invert: true}}
	}
	// an announce on a connection under inspection (a device known to run a client, to an HTTP
	// tracker on an uncommon port: decided at its SYN, so bt_tcp never sees its first data): the
	// tracker goes to bt_trackers as bt_tcp puts it there for a device not known yet (on an
	// uncommon port only: a connection to a known peer on a common port is inspected too)
	for _, signature := range [][][]expr.Any{
		{innerIs(0, signatureAnnounce)},
		{innerIs(0, signatureAnnouncePHP[:12]), innerIs(12, signatureAnnouncePHP[12:])},
	} {
		tracker := append(append([][]expr.Any{ctMarkTest(ctInspect, expr.CmpOpNeq)}, signature...), protocol(unix.IPPROTO_TCP), notCommonPort(2), ipv4(),
			devicePeerKey(), []expr.Any{update(trackers)})
		add(decided, tracker...)
	}
	add(decided, ctMarkTest(ctBitTorrent, expr.CmpOpEq), returns)
	add(decided, ipv4(), []expr.Any{addressLoad(offsetSource)}, notIn(hosts), []expr.Any{addressLoad(offsetSource), update(hosts)})
	add(decided, udp4(), endpoint(offsetSource, 0), notIn(sockets), endpoint(offsetSource, 0), []expr.Any{update(sockets)})
	add(decided, udp4(), endpoint(offsetDestination, 2), notIn(peers), endpoint(offsetDestination, 2), []expr.Any{update(peers)})
	add(decided, tcp4(), endpoint(offsetDestination, 2), notIn(peers), endpoint(offsetDestination, 2), []expr.Any{update(peers)})
	// a uTP SYN on a flow of discovery: the socket spoke DHT to this peer before its first uTP SYN
	// (qBittorrent at its start: its DHT and its uTP share the socket, and so do the peer's). The
	// flow goes through sing-box, and a connection on it would, for its whole life (the stand of
	// 2026-11-16, bypass, qBittorrent: 85 % of its UDP bytes through sing-box). The socket speaks
	// uTP from now on (its new flows are forwarded); the SYN is dropped, and the client tries the
	// peer over TCP (libtorrent does when a uTP connect fails), decided at the SYN by bt_peers.
	// Block drops the flow already (or forwards the discovery of the traffic podkop does not take).
	if mode != BitTorrentBlock {
		for _, utpSyn := range utpSyns {
			add(decided, append(append([][]expr.Any{ctMarkTest(ctDiscovery, expr.CmpOpNeq)}, utpSyn...),
				udp4(), endpoint(offsetSource, 0), []expr.Any{update(utp)}, counter, verdict(expr.VerdictDrop, ""))...)
		}
	}
	if mode == BitTorrentBlock && detector.LAN {
		add(decided, verdict(expr.VerdictGoto, block.Name))
	}

	// bt_act: what mangle marked for the proxy is podkop's; the rest goes to bt_free
	add(act, []expr.Any{
		&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: binaryutil.NativeEndian.PutUint32(markProxy), Xor: binaryutil.NativeEndian.PutUint32(0)},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(0)},
	}, verdict(expr.VerdictGoto, free.Name))
	add(act, ctMarkTest(ctIntercepted, expr.CmpOpEq), ctMarkAdd(ctIntercepted))
	// inspected: the mark stays, proxy sends it to the inspection inbound
	add(act, ctMarkTest(ctInspect, expr.CmpOpNeq), returns)
	add(act, ctMarkTest(ctBitTorrent, expr.CmpOpEq), returns)
	switch mode {
	case BitTorrentBypass:
		// an address of the FakeIP range only sing-box can turn back into its name: a tracker of a
		// list (the BitTorrent inbound sends it straight on); the discovery, for the module
		add(act, ipv4(), addressWithin(offsetDestination, rangeFakeIP), returns)
		add(act, ctMarkTest(ctDiscovery, expr.CmpOpNeq), returns)
		add(act, setMark(false), counter)
	case BitTorrentBlock:
		add(act, verdict(expr.VerdictGoto, block.Name))
	}

	// bt_free: of the traffic podkop does not take, what goes to sing-box all the same (marked for
	// the proxy here; proxy sends it to an inbound of BitTorrent by its conntrack mark). Only what
	// the device sends on a connection it began, as mangle takes: bt_act sees every packet, and a
	// connection that began outside (a port forward, UPnP) is decided by the device's answers too
	// (its answer to a DHT query is discovery, to a peer's plaintext handshake BitTorrent). Sent to
	// sing-box, its answer would leave from another port and the next packets from outside would
	// meet an inbound with no connection for them; it goes on as forwarded.
	add(free, []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Lookup{SourceRegister: 1, SetName: SetInterfaces, SetID: idInterfaces, Invert: true},
	}, returns)
	add(free, []expr.Any{
		&expr.Ct{Register: 1, Key: expr.CtKeyDIRECTION},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{ctDirectionReply}},
	}, returns)
	if detector.LAN {
		add(free, ctMarkTest(ctInspect, expr.CmpOpNeq), setMark(true), counter, returns)
	}
	add(free, ctMarkTest(ctBitTorrent, expr.CmpOpEq), returns)
	switch {
	case mode == BitTorrentSection && detector.LAN:
		add(free, setMark(true), counter)
	case mode != BitTorrentBlock:
		add(free, ctMarkTest(ctDiscovery, expr.CmpOpNeq), setMark(true), counter)
	}

	// bt_block: the discovery, the other UDP (uTP), the rest (TCP), in this order
	// (BitTorrentDrops reads them so)
	if mode == BitTorrentBlock {
		drop := verdict(expr.VerdictDrop, "")
		add(block, protocol(unix.IPPROTO_UDP), ctMarkTest(ctDiscovery, expr.CmpOpNeq), counter, drop)
		add(block, protocol(unix.IPPROTO_UDP), counter, drop)
		add(block, counter, drop)
	}

	// bt_incoming: in block, a new connection from outside (a port forward) to a client's socket,
	// of every device (LAN) or of the devices routed whole
	if mode == BitTorrentBlock {
		incoming := conn.AddChain(&nftables.Chain{Name: ChainBitTorrentIncoming, Table: table, Type: nftables.ChainTypeFilter,
			Hooknum: nftables.ChainHookForward, Priority: nftables.ChainPriorityRef(bitTorrentIncomingPriority), Policy: &accept})
		add(incoming, []expr.Any{
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Lookup{SourceRegister: 1, SetName: SetInterfaces, SetID: idInterfaces},
		}, returns)
		add(incoming, []expr.Any{
			&expr.Ct{Key: expr.CtKeySTATE, Register: 1},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: binaryutil.NativeEndian.PutUint32(expr.CtStateBitNEW), Xor: binaryutil.NativeEndian.PutUint32(0)},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(0)},
		}, returns)
		devices := []netip.Prefix{{}}
		if !detector.LAN {
			devices = detector.Sources
		}
		for _, device := range devices {
			for _, transport := range []byte{unix.IPPROTO_TCP, unix.IPPROTO_UDP} {
				rule := [][]expr.Any{ipv4()}
				if device.IsValid() {
					rule = append(rule, addressWithin(offsetDestination, device))
				}
				rule = append(rule, protocol(transport), endpoint(offsetDestination, 2), []expr.Any{inSet(sockets)}, counter, verdict(expr.VerdictDrop, ""))
				add(incoming, rule...)
			}
		}
	}
	return portsErr
}
