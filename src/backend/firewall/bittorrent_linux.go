package firewall

import (
	"time"

	"github.com/podkop-net/podkop-experimental/src/backend/dataplane"
	"github.com/sagernet/nftables"
	"github.com/sagernet/nftables/binaryutil"
	"github.com/sagernet/nftables/expr"
	"golang.org/x/sys/unix"
)

// The BitTorrent detector (notes/2026-11-15-bittorrent.md of the workspace; the prototype of the
// hand-over, research_notes/bittorrent/04).
//
// A client sends DHT, uTP and the UDP tracker over one UDP socket, and the first packet of that
// socket is a DHT query. bt_detect, before mangle, looks at the first packet of every UDP flow of
// the LAN: a signature of DHT, of a connect to a UDP tracker or of a uTP SYN puts the socket (the
// address and port of the device) in bt_sockets and the device in bt_hosts, and from then on
// every flow of that socket is BitTorrent. The far address and port a socket of a client writes
// to goes to bt_peers: a TCP connection of the device to one of them is BitTorrent by its SYN
// (qBittorrent and Transmission try uTP first, the same address and port). A plaintext handshake
// is told by the first data of a connection; a connection the proxy had taken by then stays with
// sing-box, whose route rule of the protocol leads it. The decision is kept in the conntrack mark
// of the connection: a connection never changes its way on the run.
//
// What is done with it, bt_act, after mangle and on what mangle marked for the proxy: bypass takes
// podkop's mark off (the connection is forwarded, and the router may offload it), block drops,
// section leaves the mark, and the first rules of proxy send it to the inbound of BitTorrent. With
// BlockLAN, bt_detect drops it for every device of the interfaces.
//
// Other TCP of a device running a client, to a peer not known yet: bypass leaves it to sing-box
// (owner's choice, 2026-11-15: no heuristic), section takes its connections to uncommon ports, and
// block drops a first data packet shaped like the first message of the encrypted handshake (96
// bytes of key and up to 512 of padding) to such a port, unless it begins as TLS, HTTP or SSH,
// remembering the peer for the retry.
//
// A change of the mode: a connection decided before goes on by its mark, and the new mode takes
// its next packet. The sets go into the table made anew (bitTorrentKept), and a decided connection
// puts its device, socket and peer back in them when they are not there (a table of a start has
// none). A connection the router offloads passes no rule at all: when BitTorrent leaves bypass,
// the backend ends the conntrack entries of BitTorrent (ForgetBitTorrentFlows), and the next
// packet of such a connection makes a new entry that the sets tell (a TCP packet whose SYN was
// not seen, to a peer the device knows, is taken as a plaintext handshake is).

// BitTorrent is what the firewall does with the traffic of BitTorrent clients it tells.
type BitTorrent struct {
	// Mode is "" (off), BitTorrentBypass, BitTorrentBlock or BitTorrentSection.
	Mode string
	// BlockLAN blocks it for every device of the interfaces, not only what the backend takes.
	BlockLAN bool
}

const (
	BitTorrentBypass  = "bypass"
	BitTorrentBlock   = "block"
	BitTorrentSection = "section"
)

const (
	SetBitTorrentSockets = "bt_sockets"
	SetBitTorrentHosts   = "bt_hosts"
	SetBitTorrentPeers   = "bt_peers"
)

// bitTorrentTimeout is how long a socket, a device and a peer are kept after their last packet of
// BitTorrent: the prototype's value, with which all four clients of the stand were told whole.
const bitTorrentTimeout = 30 * time.Minute

// The priorities of the chains of the detector: before mangle (filter, -150) and after it, both
// before proxy (-100).
const (
	bitTorrentDetectPriority = -160
	bitTorrentActPriority    = -149
)

const (
	ctBitTorrent  = dataplane.BitTorrentCt
	ctLate        = dataplane.BitTorrentLateCt
	ctNot         = dataplane.BitTorrentNotCt
	ctIntercepted = dataplane.InterceptedCt
	ctDecided     = ctBitTorrent | ctLate | ctNot
)

// lsdAddress is the multicast group of the local peer discovery of BitTorrent (BEP 14), port 6771.
var lsdAddress = []byte{239, 192, 152, 143}

// commonPorts are the ports a BitTorrent client does not listen on in practice and other programs
// use: the TCP of a device running a client to any other port is taken for its traffic in the mode
// section, and its first data shaped like the encrypted handshake is dropped in the mode block.
var commonPorts = []uint16{22, 25, 53, 80, 110, 123, 143, 443, 465, 587, 853, 993, 995, 3478, 5222, 5223, 5228, 8080, 8443}

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
	// is HTTP, 2026-11-15) sends no UDP the detector knows, and is told by this
	signatureAnnounce = []byte("GET /announce")
	// how TLS (a handshake record of version 3), HTTP and SSH begin: the first data of such a
	// connection is not taken for the encrypted handshake of BitTorrent in the mode block
	notBitTorrentStarts = [][]byte{{0x16, 0x03}, []byte("GET "), []byte("POST"), []byte("HEAD"), []byte("SSH-")}
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
	for _, name := range []string{SetBitTorrentSockets, SetBitTorrentHosts, SetBitTorrentPeers} {
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
	return kept
}

// bitTorrentSets adds the sets of the detector, with the elements kept of the table before.
func bitTorrentSets(conn *nftables.Conn, table *nftables.Table, nextID *uint32, kept map[string][]nftables.SetElement) (sockets, hosts, peers *nftables.Set, err error) {
	endpointType := nftables.MustConcatSetType(nftables.TypeIPAddr, nftables.TypeInetService)
	newSet := func(name string, keyType nftables.SetDatatype, concatenation bool) (*nftables.Set, error) {
		*nextID++
		set := &nftables.Set{Table: table, ID: *nextID, Name: name, KeyType: keyType, Dynamic: true, HasTimeout: true,
			Timeout: bitTorrentTimeout, Concatenation: concatenation}
		return set, conn.AddSet(set, kept[name])
	}
	if sockets, err = newSet(SetBitTorrentSockets, endpointType, true); err != nil {
		return
	}
	if hosts, err = newSet(SetBitTorrentHosts, nftables.TypeIPAddr, false); err != nil {
		return
	}
	peers, err = newSet(SetBitTorrentPeers, endpointType, true)
	return
}

// addBitTorrentProxy adds the first rules of proxy in the mode section: what bt_act left marked
// as BitTorrent goes to the inbound of BitTorrent, and is accepted there: tproxy does not end the
// rules of a chain, and the rule of the transparent proxy after it would take the packet again
// (on the stand of 2026-11-15 every packet of the inbound of BitTorrent was counted by both).
func addBitTorrentProxy(add func(*nftables.Chain, ...[]expr.Any), proxy *nftables.Chain) {
	for _, transport := range []byte{unix.IPPROTO_TCP, unix.IPPROTO_UDP} {
		add(proxy, ctMarkTest(ctBitTorrent, expr.CmpOpNeq), []expr.Any{
			&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: binaryutil.NativeEndian.PutUint32(markProxy), Xor: binaryutil.NativeEndian.PutUint32(0)},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(markProxy)},
		}, protocol(transport), []expr.Any{
			&expr.Immediate{Register: 1, Data: addressProxy.AsSlice()},
			&expr.Immediate{Register: 2, Data: binaryutil.BigEndian.PutUint16(dataplane.BitTorrentTProxyPort)},
			&expr.TProxy{Family: byte(nftables.TableFamilyIPv4), TableFamily: byte(nftables.TableFamilyINet), RegAddr: 1, RegPort: 2},
			&expr.Counter{},
			&expr.Verdict{Kind: expr.VerdictAccept},
		})
	}
}

// addBitTorrent adds the sets (with what kept holds of them) and the chains of the detector to
// the table.
func addBitTorrent(conn *nftables.Conn, table *nftables.Table, plan *Plan, add func(*nftables.Chain, ...[]expr.Any), nextID *uint32,
	kept map[string][]nftables.SetElement) error {
	mode := plan.BitTorrent.Mode
	sockets, hosts, peers, err := bitTorrentSets(conn, table, nextID, kept)
	if err != nil {
		return err
	}
	*nextID++
	ports := &nftables.Set{Table: table, ID: *nextID, Name: "__set%d", Anonymous: true, Constant: true, KeyType: nftables.TypeInetService}
	var elements []nftables.SetElement
	for _, port := range commonPorts {
		elements = append(elements, nftables.SetElement{Key: binaryutil.BigEndian.PutUint16(port)})
	}
	if mode != BitTorrentBypass {
		if err = conn.AddSet(ports, elements); err != nil {
			return err
		}
	}
	notCommonPort := func(offset uint32) []expr.Any {
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
	udp, socket, flow := chain("bt_udp"), chain("bt_socket"), chain("bt_flow")
	tcp, syn, handshake, decided := chain("bt_tcp"), chain("bt_syn"), chain("bt_handshake"), chain("bt_decided")
	act := conn.AddChain(&nftables.Chain{Name: "bt_act", Table: table, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookPrerouting, Priority: nftables.ChainPriorityRef(bitTorrentActPriority), Policy: &accept})
	returns := verdict(expr.VerdictReturn, "")
	counter := []expr.Any{&expr.Counter{}}

	// every rule that reads an address or a port says what it reads first, as nft does: the
	// listing then reads as the rules were written
	tcp4 := func() []expr.Any { return append(ipv4(), protocol(unix.IPPROTO_TCP)...) }
	udp4 := func() []expr.Any { return append(ipv4(), protocol(unix.IPPROTO_UDP)...) }
	updateHost := func() [][]expr.Any { return [][]expr.Any{ipv4(), {addressLoad(offsetSource), update(hosts)}} }

	// bt_detect: what comes from the LAN, IPv4; a connection decided before goes by its mark
	add(detect, []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Lookup{SourceRegister: 1, SetName: SetInterfaces, SetID: idInterfaces, Invert: true},
	}, returns)
	add(detect, []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{unix.NFPROTO_IPV4}},
	}, returns)
	add(detect, ctMarkTest(ctDecided, expr.CmpOpNeq), verdict(expr.VerdictGoto, decided.Name))
	add(detect, protocol(unix.IPPROTO_UDP), verdict(expr.VerdictGoto, udp.Name))
	add(detect, protocol(unix.IPPROTO_TCP), verdict(expr.VerdictGoto, tcp.Name))

	// bt_udp: the first packet of a flow
	add(udp, ipv4(), []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offsetDestination, Len: 4},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: lsdAddress},
	}, protocol(unix.IPPROTO_UDP), destinationPort(6771), []expr.Any{addressLoad(offsetSource), update(hosts), &expr.Counter{}}, returns)
	add(udp, ipv4(), addressIn(offsetDestination, SetLocal, idLocal), returns)
	add(udp, udp4(), endpoint(offsetSource, 0), []expr.Any{inSet(sockets)}, verdict(expr.VerdictGoto, flow.Name))
	for _, signature := range [][]byte{signatureDHTQuery, signatureDHTResponse, signatureDHTAddress, signatureDHTError, signatureTracker} {
		add(udp, innerIs(0, signature), counter, verdict(expr.VerdictGoto, socket.Name))
	}
	// a uTP SYN of version 1, an extension of a known type or none, a timestamp difference of 0
	add(udp, innerIs(0, []byte{0x41}), []expr.Any{
		inner(1, 1), &expr.Cmp{Op: expr.CmpOpLt, Register: 1, Data: []byte{3}},
	}, innerIs(8, []byte{0, 0, 0, 0}), counter, verdict(expr.VerdictGoto, socket.Name))
	add(udp, ctMarkAdd(ctNot))

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
	// tracker's, not of the swarm
	announce := append([][]expr.Any{innerIs(0, signatureAnnounce)}, updateHost()...)
	add(tcp, append(announce, ctMarkAdd(ctNot), counter, returns)...)
	if mode == BitTorrentBlock {
		// a first data packet that begins as TLS, HTTP or SSH is none of BitTorrent's, as the
		// prototype took it
		for _, start := range notBitTorrentStarts {
			add(tcp, innerIs(0, start), ctMarkAdd(ctNot), returns)
		}
		// the first message of the encrypted handshake: 96 to 608 bytes of payload, with the
		// headers of IPv4 and TCP 136 to 668
		rule := [][]expr.Any{ipv4(), addressIn(offsetSource, SetBitTorrentHosts, hosts.ID), protocol(unix.IPPROTO_TCP),
			notCommonPort(2), hasPayload(), {
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 2, Len: 2},
				&expr.Range{Op: expr.CmpOpEq, Register: 1, FromData: binaryutil.BigEndian.PutUint16(136), ToData: binaryutil.BigEndian.PutUint16(668)},
			}}
		if !plan.BitTorrent.BlockLAN {
			rule = append(rule, ctMarkTest(ctIntercepted, expr.CmpOpNeq))
		}
		rule = append(rule, endpoint(offsetDestination, 2), []expr.Any{update(peers)}, ctMarkAdd(ctBitTorrent), counter,
			verdict(expr.VerdictDrop, ""))
		add(tcp, rule...)
	}
	// a packet of a connection whose SYN this table did not see, or saw before its peer was known
	// (the entry of a connection ForgetBitTorrentFlows ended makes a new one with its next packet):
	// a device running a client, to a peer it knows, is taken as a plaintext handshake is; after
	// the rules of block, whose drop of the encrypted handshake comes first
	add(tcp, ipv4(), addressIn(offsetSource, SetBitTorrentHosts, hosts.ID), protocol(unix.IPPROTO_TCP), endpoint(offsetDestination, 2),
		[]expr.Any{inSet(peers)}, counter, verdict(expr.VerdictGoto, handshake.Name))
	add(tcp, hasPayload(), ctMarkAdd(ctNot))

	// bt_syn: a connection of a device running a client to a peer it knows, or in the mode section
	// to an uncommon port
	add(syn, ipv4(), addressIn(offsetSource, SetBitTorrentHosts, hosts.ID), protocol(unix.IPPROTO_TCP), endpoint(offsetDestination, 2),
		[]expr.Any{inSet(peers)}, ctMarkAdd(ctBitTorrent), counter, verdict(expr.VerdictGoto, decided.Name))
	if mode == BitTorrentSection {
		add(syn, ipv4(), addressIn(offsetSource, SetBitTorrentHosts, hosts.ID), protocol(unix.IPPROTO_TCP), notCommonPort(2),
			ctMarkAdd(ctBitTorrent), counter, verdict(expr.VerdictGoto, decided.Name))
	}

	// bt_handshake: the plaintext handshake; a connection the proxy has taken stays with sing-box
	add(handshake, updateHost()...)
	add(handshake, tcp4(), endpoint(offsetDestination, 2), []expr.Any{update(peers)})
	add(handshake, ctMarkTest(ctIntercepted, expr.CmpOpNeq), ctMarkAdd(ctLate), counter, returns)
	add(handshake, ctMarkAdd(ctBitTorrent), counter, verdict(expr.VerdictGoto, decided.Name))

	// bt_decided: a connection of BitTorrent, for every device with BlockLAN. While it lasts, its
	// device, its socket and its peer are put back in the sets when they are not there: a table
	// made when the backend started has none, and a device whose connections were decided before
	// (their marks are in conntrack) is told again at their next packets, its new connections with
	// it (on the stand of 2026-11-15, a restart of podkop in the mode block let the encrypted
	// retry of a blocked connection through: the device was in no set)
	notIn := func(set *nftables.Set) []expr.Any {
		return []expr.Any{&expr.Lookup{SourceRegister: 1, SetName: set.Name, SetID: set.ID, Invert: true}}
	}
	add(decided, ctMarkTest(ctBitTorrent, expr.CmpOpEq), returns)
	add(decided, ipv4(), []expr.Any{addressLoad(offsetSource)}, notIn(hosts), []expr.Any{addressLoad(offsetSource), update(hosts)})
	add(decided, udp4(), endpoint(offsetSource, 0), notIn(sockets), endpoint(offsetSource, 0), []expr.Any{update(sockets)})
	add(decided, udp4(), endpoint(offsetDestination, 2), notIn(peers), endpoint(offsetDestination, 2), []expr.Any{update(peers)})
	add(decided, tcp4(), endpoint(offsetDestination, 2), notIn(peers), endpoint(offsetDestination, 2), []expr.Any{update(peers)})
	if mode == BitTorrentBlock && plan.BitTorrent.BlockLAN {
		add(decided, counter, verdict(expr.VerdictDrop, ""))
	}

	// bt_act: what mangle marked for the proxy
	add(act, []expr.Any{
		&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: binaryutil.NativeEndian.PutUint32(markProxy), Xor: binaryutil.NativeEndian.PutUint32(0)},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(0)},
	}, returns)
	add(act, ctMarkTest(ctIntercepted, expr.CmpOpEq), ctMarkAdd(ctIntercepted))
	add(act, ctMarkTest(ctBitTorrent, expr.CmpOpEq), returns)
	switch mode {
	case BitTorrentBypass:
		add(act, []expr.Any{
			&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: binaryutil.NativeEndian.PutUint32(^uint32(markProxy)), Xor: binaryutil.NativeEndian.PutUint32(0)},
			&expr.Meta{Key: expr.MetaKeyMARK, SourceRegister: true, Register: 1},
		}, counter)
	case BitTorrentBlock:
		add(act, counter, verdict(expr.VerdictDrop, ""))
	}
	return nil
}
