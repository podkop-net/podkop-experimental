package diag

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mdlayher/netlink"
	"github.com/podkop-net/podkop-experimental/src/backend/dataplane"
	"github.com/podkop-net/podkop-experimental/src/backend/firewall"
	E "github.com/sagernet/sing/common/exceptions"
	"golang.org/x/sys/unix"
)

// Trace is the trace of the packets of a check a device makes (firewall.ArmTrace), heard
// from the kernel over netlink: the group of the traces of nf_tables. "nft monitor trace"
// would tell the same, but it reads the whole ruleset with the elements of every set
// before it listens: with a set of 100 000 subnets it takes 143 MB and 2 s, with 300 000
// 425 MB and 13 s (OpenWrt 24.10, nft 1.1.1), more than a router may have. The events
// name a rule by its handle; the text of the rules a packet met is read afterwards, chain
// by chain (nft list chain reads no elements of named sets).
type Trace struct {
	conn   *netlink.Conn
	table  string
	access sync.Mutex
	events []traceEvent
	// lost tells that the kernel dropped events: the buffer of the socket was full
	lost bool
	done chan struct{}
}

// traceEventsKept bounds what a trace keeps: a check makes a few packets a second, each a
// few dozen events.
const traceEventsKept = 20000

// StartTrace listens to the traces of the kernel and arms the trace of the packets of a
// check (firewall.ArmTrace): the TCP packets to the FakeIP range and a port, the DNS
// questions for the check name of a label. The listener is there first: a packet traced
// before it would be told to nobody.
func StartTrace(port uint16, label string) (*Trace, error) {
	conn, err := netlink.Dial(unix.NETLINK_NETFILTER, nil)
	if err != nil {
		return nil, E.Cause(err, "open netlink")
	}
	err = conn.JoinGroup(unix.NFNLGRP_NFTRACE)
	if err != nil {
		conn.Close()
		return nil, E.Cause(err, "listen to the traces of nf_tables")
	}
	// a burst of events must not be lost while the reader is busy
	_ = conn.SetReadBuffer(1 << 20)
	trace := &Trace{conn: conn, table: firewall.TraceTableFor(port), done: make(chan struct{})}
	go trace.read()
	err = firewall.ArmTrace(port, label)
	if err != nil {
		conn.Close()
		<-trace.done
		return nil, err
	}
	return trace, nil
}

func (t *Trace) read() {
	defer close(t.done)
	for {
		messages, err := t.conn.Receive()
		if err != nil {
			if errors.Is(err, unix.ENOBUFS) {
				t.access.Lock()
				t.lost = true
				t.access.Unlock()
				continue
			}
			// the socket was closed by Stop, or broke
			return
		}
		for _, message := range messages {
			event, ok := decodeTraceMessage(message)
			if !ok {
				continue
			}
			t.access.Lock()
			if len(t.events) < traceEventsKept {
				t.events = append(t.events, event)
			}
			t.access.Unlock()
		}
	}
}

// Stop removes the trace table, ends the listener and returns what it heard, as lines of
// the form "nft monitor trace" writes (the text of each rule read from its chain). The
// table of this check is named as the one of every check ("inet PodkopTrace trace");
// what the tables of other checks traced meanwhile is left out.
func (t *Trace) Stop() []string {
	_ = firewall.DisarmTrace(t.table)
	t.conn.Close()
	<-t.done
	t.access.Lock()
	events, lost := t.events, t.lost
	t.access.Unlock()
	lines := traceText(events, t.table, ruleTexts(events))
	if lost {
		lines = append(lines, "lost: the kernel dropped some events of the trace")
	}
	return lines
}

// traceEvent is one event of a trace as the kernel tells it (nft_trace_notify).
type traceEvent struct {
	id                 uint32
	family             uint8
	table, chain       string
	kind               uint32
	handle             uint64
	verdict            int32
	verdictChain       string
	policy             uint32
	hasPolicy          bool
	nfproto            uint32
	iif, oif           uint32
	network, transport []byte
}

// the attributes of a trace (enum nft_trace_attributes), its types and the message
const (
	attrTable           = unix.NFTA_TRACE_TABLE
	attrChain           = unix.NFTA_TRACE_CHAIN
	attrRuleHandle      = unix.NFTA_TRACE_RULE_HANDLE
	attrType            = unix.NFTA_TRACE_TYPE
	attrVerdict         = unix.NFTA_TRACE_VERDICT
	attrID              = unix.NFTA_TRACE_ID
	attrNetworkHeader   = unix.NFTA_TRACE_NETWORK_HEADER
	attrTransportHeader = unix.NFTA_TRACE_TRANSPORT_HEADER
	attrIIF             = unix.NFTA_TRACE_IIF
	attrOIF             = unix.NFTA_TRACE_OIF
	attrNFProto         = unix.NFTA_TRACE_NFPROTO
	attrPolicy          = unix.NFTA_TRACE_POLICY

	verdictCode  = unix.NFTA_VERDICT_CODE
	verdictChain = unix.NFTA_VERDICT_CHAIN

	traceTypePolicy = unix.NFT_TRACETYPE_POLICY
	traceTypeReturn = unix.NFT_TRACETYPE_RETURN
	traceTypeRule   = unix.NFT_TRACETYPE_RULE

	nfnlSubsysNFTables = unix.NFNL_SUBSYS_NFTABLES
	nftMsgTrace        = unix.NFT_MSG_TRACE
)

func decodeTraceMessage(message netlink.Message) (traceEvent, bool) {
	if message.Header.Type != netlink.HeaderType(nfnlSubsysNFTables<<8|nftMsgTrace) || len(message.Data) < 4 {
		return traceEvent{}, false
	}
	event := traceEvent{family: message.Data[0]}
	decoder, err := netlink.NewAttributeDecoder(message.Data[4:])
	if err != nil {
		return traceEvent{}, false
	}
	decoder.ByteOrder = binary.BigEndian
	for decoder.Next() {
		switch decoder.Type() {
		case attrTable:
			event.table = decoder.String()
		case attrChain:
			event.chain = decoder.String()
		case attrRuleHandle:
			event.handle = decoder.Uint64()
		case attrType:
			event.kind = decoder.Uint32()
		case attrVerdict:
			decoder.Nested(func(nested *netlink.AttributeDecoder) error {
				nested.ByteOrder = binary.BigEndian
				for nested.Next() {
					switch nested.Type() {
					case verdictCode:
						event.verdict = int32(nested.Uint32())
					case verdictChain:
						event.verdictChain = nested.String()
					}
				}
				return nil
			})
		case attrID:
			event.id = decoder.Uint32()
		case attrNetworkHeader:
			event.network = decoder.Bytes()
		case attrTransportHeader:
			event.transport = decoder.Bytes()
		case attrIIF:
			event.iif = decoder.Uint32()
		case attrOIF:
			event.oif = decoder.Uint32()
		case attrNFProto:
			event.nfproto = decoder.Uint32()
		case attrPolicy:
			event.policy, event.hasPolicy = decoder.Uint32(), true
		}
	}
	if decoder.Err() != nil || event.table == "" || event.chain == "" {
		return traceEvent{}, false
	}
	return event, true
}

func familyName(family uint8) string {
	switch family {
	case unix.NFPROTO_INET:
		return "inet"
	case unix.NFPROTO_IPV4:
		return "ip"
	case unix.NFPROTO_IPV6:
		return "ip6"
	case unix.NFPROTO_ARP:
		return "arp"
	case unix.NFPROTO_BRIDGE:
		return "bridge"
	case unix.NFPROTO_NETDEV:
		return "netdev"
	}
	return strconv.Itoa(int(family))
}

func verdictName(code int32, chain string) string {
	switch code {
	case 0:
		return "drop"
	case 1:
		return "accept"
	case 2:
		return "stolen"
	case 3:
		return "queue"
	case 4:
		return "repeat"
	case -1:
		return "continue"
	case -2:
		return "break"
	case -3:
		return "jump " + chain
	case -4:
		return "goto " + chain
	case -5:
		return "return"
	}
	return strconv.Itoa(int(code))
}

// ruleTexts reads the rules of the chains the events name a rule of: "family table chain"
// → handle → text, as nft writes them. A chain that cannot be read in the time left is
// left out: its rules are named by their handle.
func ruleTexts(events []traceEvent) map[string]map[uint64]string {
	// the report waits for this: a few chains, each read in a fraction of a second
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	texts := make(map[string]map[uint64]string)
	for _, event := range events {
		if event.kind != traceTypeRule {
			continue
		}
		key := familyName(event.family) + " " + event.table + " " + event.chain
		if _, read := texts[key]; read {
			continue
		}
		texts[key] = readChain(ctx, familyName(event.family), event.table, event.chain)
	}
	return texts
}

func readChain(ctx context.Context, family, table, chain string) map[uint64]string {
	rules := make(map[uint64]string)
	output, err := exec.CommandContext(ctx, "nft", "-a", "list", "chain", family, table, chain).Output()
	if err != nil {
		return rules
	}
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		text, number, found := strings.Cut(line, " # handle ")
		if !found || strings.HasSuffix(text, "{") {
			continue
		}
		handle, err := strconv.ParseUint(number, 10, 64)
		if err == nil {
			rules[handle] = text
		}
	}
	return rules
}

// traceText writes the events as "nft monitor trace" does: "trace id <id> <family>
// <table> <chain> " and then "packet: <fields>" where the kernel told the headers of the
// packet (the first event of each base chain), "rule <text> (verdict <verdict>)",
// "verdict <verdict>" or "policy <verdict>". The table of this check is written as
// firewall.TraceTable; the events of the tables of other checks are left out.
func traceText(events []traceEvent, own string, texts map[string]map[uint64]string) []string {
	var lines []string
	interfaces := make(map[uint32]string)
	for _, event := range events {
		table := event.table
		if strings.HasPrefix(table, firewall.TraceTable) {
			if table != own {
				continue
			}
			table = firewall.TraceTable
		}
		chain := familyName(event.family) + " " + event.table + " " + event.chain
		prefix := fmt.Sprintf("trace id %08x %s %s %s ", event.id, familyName(event.family), table, event.chain)
		if len(event.network) > 0 {
			lines = append(lines, prefix+"packet: "+packetFields(event, interfaces))
		}
		switch event.kind {
		case traceTypeRule:
			text, known := texts[chain][event.handle]
			if !known {
				text = "handle " + strconv.FormatUint(event.handle, 10)
			}
			lines = append(lines, prefix+"rule "+text+" (verdict "+verdictName(event.verdict, event.verdictChain)+")")
		case traceTypeReturn:
			lines = append(lines, prefix+"verdict "+verdictName(event.verdict, event.verdictChain))
		case traceTypePolicy:
			policy := "accept"
			if event.hasPolicy && event.policy == 0 {
				policy = "drop"
			}
			lines = append(lines, prefix+"policy "+policy)
		}
	}
	return lines
}

// packetFields writes what the parsing of a trace reads of a packet, as nft writes it:
// the input device, the addresses, and the ports and flags of TCP or UDP.
func packetFields(event traceEvent, interfaces map[uint32]string) string {
	var fields []string
	device := func(index uint32) string {
		name, known := interfaces[index]
		if !known {
			if found, err := net.InterfaceByIndex(int(index)); err == nil {
				name = found.Name
			} else {
				name = strconv.Itoa(int(index))
			}
			interfaces[index] = name
		}
		return name
	}
	if event.iif != 0 {
		fields = append(fields, `iif "`+device(event.iif)+`"`)
	}
	// the interface a forwarded packet leaves by
	if event.oif != 0 {
		fields = append(fields, `oif "`+device(event.oif)+`"`)
	}
	header := event.network
	var protocol byte
	switch {
	case len(header) >= 20 && header[0]>>4 == 4:
		source, _ := netip.AddrFromSlice(header[12:16])
		destination, _ := netip.AddrFromSlice(header[16:20])
		protocol = header[9]
		fields = append(fields, "ip saddr "+source.String(), "ip daddr "+destination.String())
	case len(header) >= 40 && header[0]>>4 == 6:
		source, _ := netip.AddrFromSlice(header[8:24])
		destination, _ := netip.AddrFromSlice(header[24:40])
		protocol = header[6]
		fields = append(fields, "ip6 saddr "+source.String(), "ip6 daddr "+destination.String())
	}
	transport := event.transport
	switch {
	case protocol == unix.IPPROTO_TCP && len(transport) >= 14:
		fields = append(fields, "ip protocol tcp",
			"tcp sport "+strconv.Itoa(int(binary.BigEndian.Uint16(transport[0:]))),
			"tcp dport "+strconv.Itoa(int(binary.BigEndian.Uint16(transport[2:]))),
			"tcp flags == "+tcpFlagNames(transport[13]))
	case protocol == unix.IPPROTO_UDP && len(transport) >= 8:
		fields = append(fields, "ip protocol udp",
			"udp sport "+strconv.Itoa(int(binary.BigEndian.Uint16(transport[0:]))),
			"udp dport "+strconv.Itoa(int(binary.BigEndian.Uint16(transport[2:]))),
			"udp length "+strconv.Itoa(int(binary.BigEndian.Uint16(transport[4:]))))
	}
	return strings.Join(fields, " ")
}

func tcpFlagNames(value byte) string {
	var names []string
	for bit, name := range []string{"fin", "syn", "rst", "psh", "ack", "urg", "ecn", "cwr"} {
		if value&(1<<bit) != 0 {
			names = append(names, name)
		}
	}
	return strings.Join(names, " | ")
}

// tracedPacket is what a trace tells of one packet of a check.
type tracedPacket struct {
	// question: a DNS question for the check name, not a TCP packet of its connection;
	// redirected: sent to another destination by NAT
	question, redirected bool
	flags                string
	// source and destination are the addresses of the packet
	source, destination netip.Addr
	// hooks are the hooks of the base chains it passed, in order
	hooks []string
	// marked: the rule of podkop gave it the mark; proxied: the transparent proxy rule of
	// podkop took it
	marked, proxied bool
	// steps are what the rules of other tables and of podkop did to it, in their order
	steps []string
	// dropped is the rule (or the policy of a chain) that dropped or rejected it
	dropped string
	// iif is the interface it came in on; the rules of other tables that sent it elsewhere
	// (redirect), took it for another transparent proxy (otherProxy) or replaced the mark
	// of podkop (markReplaced)
	iif, oif                           string
	redirect, otherProxy, markReplaced string
}

// traceLine is one line of nft monitor trace: "trace id <id> <family> <table> <chain>
// packet: <fields>", "... rule <rule> (verdict <verdict>)", "... verdict <verdict> ...",
// "... policy <verdict> ...".
type traceLine struct {
	id, chain, kind, text, verdict string
}

var (
	counters = regexp.MustCompile(` ?counter packets [0-9]+ bytes [0-9]+`)
	// a rule that sends a packet elsewhere than its destination: a DNS question to another
	// server ("dnat ip to 192.168.1.2:53", "redirect to :5353", a bare "redirect")
	redirects = regexp.MustCompile(`(^| )((dnat|tproxy)( ip6?)? to |redirect( to |$| comment ))`)
)

func parseTraceLine(line string) (traceLine, bool) {
	fields := strings.SplitN(line, " ", 7)
	if len(fields) < 7 || fields[0] != "trace" || fields[1] != "id" {
		return traceLine{}, false
	}
	event := traceLine{id: fields[2], chain: fields[3] + " " + fields[4] + " " + fields[5]}
	rest := fields[6]
	switch {
	case strings.HasPrefix(rest, "packet: "):
		event.kind, event.text = "packet", strings.TrimPrefix(rest, "packet: ")
	case strings.HasPrefix(rest, "rule "):
		event.kind = "rule"
		text := strings.TrimPrefix(rest, "rule ")
		if open := strings.LastIndex(text, " (verdict "); open >= 0 && strings.HasSuffix(text, ")") {
			event.verdict = strings.TrimSuffix(text[open+len(" (verdict "):], ")")
			text = text[:open]
		}
		// the counters of a rule say nothing of this packet
		event.text = counters.ReplaceAllString(text, "")
	case strings.HasPrefix(rest, "verdict "), strings.HasPrefix(rest, "policy "):
		kind, after, _ := strings.Cut(rest, " ")
		event.kind = kind
		event.verdict, _, _ = strings.Cut(after, " ")
	default:
		return traceLine{}, false
	}
	return event, true
}

// packetsOfTrace reads the packets of a trace. A packet begins where it enters the chain of
// the trace table; the lines of packets traced at once may be mixed, and are told apart by
// their trace id. hooks names the hook of each base chain ("family table chain").
func packetsOfTrace(lines []string, hooks map[string]string) []*tracedPacket {
	traceChain := "inet " + firewall.TraceTable + " trace"
	ourTable := "inet " + dataplane.FirewallTable + " "
	markOfPodkop := "meta mark set 0x" + strconv.FormatUint(dataplane.ProxyMark+0x100000000, 16)[1:]
	current := make(map[string]*tracedPacket)
	var packets []*tracedPacket
	for _, line := range lines {
		event, ok := parseTraceLine(line)
		if !ok {
			continue
		}
		if event.kind == "packet" && event.chain == traceChain {
			packet := &tracedPacket{question: strings.Contains(event.text+" ", " udp dport 53 "), flags: tcpFlags(event.text),
				source: packetAddress(event.text, "saddr"), destination: packetAddress(event.text, "daddr"), iif: packetDevice(event.text, "iif")}
			current[event.id] = packet
			packets = append(packets, packet)
			continue
		}
		packet := current[event.id]
		if packet == nil || event.chain == traceChain {
			continue
		}
		ours := strings.HasPrefix(event.chain, ourTable)
		switch event.kind {
		case "packet":
			if hook, known := hooks[event.chain]; known && (len(packet.hooks) == 0 || packet.hooks[len(packet.hooks)-1] != hook) {
				packet.hooks = append(packet.hooks, hook)
			}
			if packet.oif == "" {
				packet.oif = packetDevice(event.text, "oif")
			}
		case "rule":
			switch {
			case packet.question:
				// the rules of podkop do not take DNS questions; what may is another
				// table that sends them to a server of its own. NAT is decided by the
				// first packet of a flow: a later one is told by the rule of that
				// table that matches a flow whose destination was rewritten (the one
				// of podkop that leaves such flows alone is no news)
				switch {
				case ours:
				case redirects.MatchString(event.text):
					packet.redirected, packet.redirect = true, event.chain+": "+event.text
					packet.steps = append(packet.steps, "sent elsewhere by "+packet.redirect)
				case strings.Contains(event.text, "ct status dnat") && !packet.redirected:
					packet.redirected, packet.redirect = true, event.chain+": "+event.text
					packet.steps = append(packet.steps, "sent elsewhere as the first question of its flow was ("+packet.redirect+")")
				}
			case ours && strings.Contains(event.text, markOfPodkop) && !packet.marked:
				packet.marked = true
				packet.steps = append(packet.steps, "marked by podkop")
			case ours && strings.Contains(event.text, " tproxy ") && !packet.proxied:
				packet.proxied = true
				packet.steps = append(packet.steps, "taken by podkop's transparent proxy")
			case !ours && strings.Contains(event.text, " tproxy "):
				// a mark it sets is told with it
				packet.otherProxy = event.chain + ": " + event.text
				packet.steps = append(packet.steps, "taken by another transparent proxy ("+packet.otherProxy+")")
			case !ours && strings.Contains(event.text, "mark set ") && packet.marked:
				// a mark set before the one of podkop is replaced by it: no matter
				packet.markReplaced = event.chain + ": " + event.text
				packet.steps = append(packet.steps, "its mark replaced by a rule of another table ("+packet.markReplaced+")")
			}
			if (event.verdict == "drop" || event.verdict == "reject") && packet.dropped == "" {
				packet.dropped = event.chain + ": " + event.text
			}
		case "policy":
			if event.verdict == "drop" && packet.dropped == "" {
				packet.dropped = event.chain + ": the policy of the chain"
			}
		}
	}
	return packets
}

// packetDevice reads a device of the fields of a traced packet: `iif "br-lan"`, `oif "wan"`.
func packetDevice(fields string, field string) string {
	_, after, found := strings.Cut(fields, field+` "`)
	if !found {
		return ""
	}
	name, _, _ := strings.Cut(after, `"`)
	return name
}

// tcpFlags reads the TCP flags of the fields of a traced packet: "syn", "ack", "psh | ack".
// Some versions of nft write those of a set of several as a number (0x18).
func tcpFlags(fields string) string {
	_, after, found := strings.Cut(fields, "tcp flags == ")
	if !found {
		return "tcp"
	}
	// the flags run up to the next field of the packet
	if end := strings.Index(after, " tcp "); end >= 0 {
		after = after[:end]
	}
	after = strings.TrimSpace(after)
	value, err := strconv.ParseUint(strings.TrimPrefix(after, "0x"), 16, 8)
	if !strings.HasPrefix(after, "0x") || err != nil {
		return after
	}
	return tcpFlagNames(byte(value))
}

// packetAddress reads an address of the fields of a traced packet: "ip saddr 192.168.1.10"
// or "ip6 saddr fd00::10" for the field "saddr".
func packetAddress(fields string, field string) netip.Addr {
	for _, family := range []string{"ip ", "ip6 "} {
		_, after, found := strings.Cut(fields, family+field+" ")
		if !found {
			continue
		}
		text, _, _ := strings.Cut(after, " ")
		address, err := netip.ParseAddr(text)
		if err == nil {
			return address
		}
	}
	return netip.Addr{}
}

// story tells what became of a packet, as facts in their order.
func (p *tracedPacket) story() string {
	var steps []string
	if p.question {
		steps = append(steps, p.steps...)
	} else if !p.marked {
		steps = append(steps, "not marked by podkop")
	}
	if !p.question {
		steps = append(steps, p.steps...)
	}
	if p.marked && !p.proxied {
		steps = append(steps, "not taken by podkop's transparent proxy")
	}
	steps = append(steps, p.outcome())
	return strings.Join(steps, " → ")
}

// outcome tells where a packet ended: dropped, forwarded through the router (the hook
// forward), delivered to the router itself (input), or neither after the routing.
func (p *tracedPacket) outcome() string {
	switch {
	case p.dropped != "":
		return "dropped by " + p.dropped
	case slices.Contains(p.hooks, "forward") && p.oif != "":
		return "forwarded through the router, out on " + p.oif
	case slices.Contains(p.hooks, "forward"):
		return "forwarded through the router"
	case slices.Contains(p.hooks, "input"):
		return "delivered to the router"
	default:
		return "lost after the routing: neither delivered to the router nor forwarded"
	}
}

// TraceVerdict tells in a sentence why the packets of a check that did not come to podkop
// did not, from the first packet of the most telling fate: a drop, another table that took
// them elsewhere, podkop's mark or transparent proxy that did not take them, a destination
// past the router. Empty when no packet of the kind was traced. sources are the interfaces
// podkop takes traffic from.
func TraceVerdict(lines []string, hooks map[string]string, questions bool, sources []string) string {
	var packets []*tracedPacket
	for _, packet := range packetsOfTrace(lines, hooks) {
		if packet.question == questions {
			packets = append(packets, packet)
		}
	}
	if len(packets) == 0 {
		return ""
	}
	first := func(test func(*tracedPacket) bool) *tracedPacket {
		for _, packet := range packets {
			if test(packet) {
				return packet
			}
		}
		return nil
	}
	forwarded := func(p *tracedPacket) bool { return p.dropped == "" && slices.Contains(p.hooks, "forward") }
	delivered := func(p *tracedPacket) bool {
		return p.dropped == "" && slices.Contains(p.hooks, "input") && !slices.Contains(p.hooks, "forward")
	}
	if p := first(func(p *tracedPacket) bool { return p.dropped != "" }); p != nil {
		return "a rule of the firewall drops them (" + p.dropped + ")"
	}
	if questions {
		if p := first(func(p *tracedPacket) bool { return p.redirect != "" }); p != nil {
			return "a rule of the firewall sends them to another DNS server (" + p.redirect + ")"
		}
		if p := first(forwarded); p != nil {
			out := ""
			if p.oif != "" {
				out = " (out on " + p.oif + ")"
			}
			return "the device " + p.source.String() + " asks the DNS server " + p.destination.String() + ", not the router: the router passes its questions on to that server" + out + ", and podkop never sees them"
		}
		if p := first(delivered); p != nil {
			return "they reach the router (" + p.destination.String() + "), but its DNS server does not pass them to podkop: see the lines 'DNS on' above"
		}
		return "the kernel loses them after the routing"
	}
	if p := first(func(p *tracedPacket) bool { return p.otherProxy != "" }); p != nil {
		return "another transparent proxy takes them (" + p.otherProxy + ")"
	}
	if p := first(func(p *tracedPacket) bool { return p.markReplaced != "" }); p != nil {
		return "a rule of another table replaces podkop's mark on them (" + p.markReplaced + ")"
	}
	if p := first(func(p *tracedPacket) bool { return !p.marked }); p != nil {
		if p.iif != "" && len(sources) > 0 && !slices.Contains(sources, p.iif) {
			return "they come in on " + p.iif + ", which is not one of the interfaces podkop takes traffic from (" + strings.Join(sources, ", ") + ")"
		}
		return "podkop's rules do not mark them"
	}
	if p := first(func(p *tracedPacket) bool { return p.proxied && !forwarded(p) && !delivered(p) }); p != nil {
		return "podkop's transparent proxy takes them, but the routing does not deliver them to the router: see the line 'Marked packets' above"
	}
	if p := first(forwarded); p != nil {
		return "they pass through the router without podkop"
	}
	return "they reach the router, but not podkop"
}

// TraceStories tells what became of the packets of a trace, those of the connection of a
// check or its DNS questions: each different story once, with the TCP flags (or the
// addresses a question was sent to) of the packets it is the story of, the first few.
func TraceStories(lines []string, hooks map[string]string, questions bool) []string {
	type told struct {
		kinds []string
		count int
	}
	stories := make(map[string]*told)
	var order []string
	for _, packet := range packetsOfTrace(lines, hooks) {
		if packet.question != questions {
			continue
		}
		story := packet.story()
		if stories[story] == nil {
			stories[story] = &told{}
			order = append(order, story)
		}
		entry := stories[story]
		entry.count++
		kind := strings.ToUpper(packet.flags)
		if questions {
			kind = packet.destination.String()
		}
		if !slices.Contains(entry.kinds, kind) {
			entry.kinds = append(entry.kinds, kind)
		}
	}
	var result []string
	for index, story := range order {
		if index == 4 {
			result = append(result, strconv.Itoa(len(order)-index)+" more ways")
			break
		}
		entry := stories[story]
		kinds := strings.Join(entry.kinds, ", ")
		if questions {
			kinds = "to " + kinds
		}
		result = append(result, kinds+" ("+strconv.Itoa(entry.count)+"): "+story)
	}
	return result
}

// TraceSource is the address the traced packets of a check came from: the device, when its
// connection did not come to sing-box and so did not tell it.
func TraceSource(lines []string, hooks map[string]string) netip.Addr {
	for _, packet := range packetsOfTrace(lines, hooks) {
		if packet.source.IsValid() {
			return packet.source
		}
	}
	return netip.Addr{}
}
