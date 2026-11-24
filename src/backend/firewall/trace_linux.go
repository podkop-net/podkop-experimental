package firewall

import (
	"slices"
	"strconv"
	"strings"

	"github.com/sagernet/nftables"
	"github.com/sagernet/nftables/expr"
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

// TraceTable begins the name of the table of the trace of a check (ArmTrace), which ends
// with the port of the check: each check has a table of its own, so two checks at once
// trace each its own packets. The updates of the backend's table do not take a trace away
// while a check runs, and a table a check left (its process killed) is found by the name.
const TraceTable = "PodkopTrace"

// TraceTableFor names the table of the trace of a check with a port.
func TraceTableFor(port uint16) string {
	return TraceTable + strconv.Itoa(int(port))
}

const (
	traceChain = "trace"
	// tracePriority is before every hook of prerouting there is (raw is -300): every rule
	// of every table a traced packet passes is told
	tracePriority = -400
)

// ArmTrace has the kernel trace the packets of a check a device makes (global_check) with
// the check name of a label and a port of its own: the TCP packets to the FakeIP range and
// that port, and the DNS questions over UDP for that name, to any address. "nft monitor
// trace" then hears of every rule of every table they pass, with its verdict and the mark
// of the packet. A trace table that is there already is replaced.
func ArmTrace(port uint16, label string) error {
	conn, err := nftables.New()
	if err != nil {
		return E.Cause(err, "open netlink")
	}
	table := &nftables.Table{Family: nftables.TableFamilyINet, Name: TraceTableFor(port)}
	if names, _ := traceTables(conn); slices.Contains(names, table.Name) {
		conn.DelTable(table)
	}
	conn.AddTable(table)
	accept := nftables.ChainPolicyAccept
	chain := conn.AddChain(&nftables.Chain{Name: traceChain, Table: table, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookPrerouting, Priority: nftables.ChainPriorityRef(tracePriority), Policy: &accept})
	for _, match := range [][][]expr.Any{
		{ipv4(), addressWithin(offsetDestination, rangeFakeIP), protocol(unix.IPPROTO_TCP), destinationPort(port)},
		{protocol(unix.IPPROTO_UDP), destinationPort(53), questionFor(label)},
	} {
		var expressions []expr.Any
		for _, part := range match {
			expressions = append(expressions, part...)
		}
		expressions = append(expressions,
			&expr.Immediate{Register: 1, Data: []byte{1}},
			&expr.Meta{Key: expr.MetaKeyNFTRACE, SourceRegister: true, Register: 1})
		conn.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: expressions})
	}
	err = conn.Flush()
	if err != nil {
		return E.Cause(err, "add the trace table")
	}
	return nil
}

// questionOffset is where the name a DNS message over UDP asks for begins, counted from the
// UDP header: after that header (8 bytes) and the one of DNS (12).
const questionOffset = 20

// questionFor matches a DNS question for a name whose first label is label: the name is
// written as the length of that label and its letters. A register holds 16 bytes; that
// much of a check label tells it apart.
func questionFor(label string) []expr.Any {
	name := append([]byte{byte(len(label))}, label...)
	if len(name) > 16 {
		name = name[:16]
	}
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: questionOffset, Len: uint32(len(name))},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: name},
	}
}

// DisarmTrace removes the trace table of a check. Its absence is no error.
func DisarmTrace(name string) error {
	return removeTraceTables(func(table string) bool { return table == name })
}

// DisarmTraces removes the trace tables every check left: the backend calls it when it
// starts, for those of checks whose process was killed.
func DisarmTraces() error {
	return removeTraceTables(func(string) bool { return true })
}

func removeTraceTables(pick func(string) bool) error {
	conn, err := nftables.New()
	if err != nil {
		return E.Cause(err, "open netlink")
	}
	names, err := traceTables(conn)
	if err != nil {
		return err
	}
	removed := false
	for _, name := range names {
		if pick(name) {
			conn.DelTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: name})
			removed = true
		}
	}
	if !removed {
		return nil
	}
	return conn.Flush()
}

// traceTables names the trace tables there are.
func traceTables(conn *nftables.Conn) ([]string, error) {
	tables, err := conn.ListTables()
	if err != nil {
		return nil, E.Cause(err, "list the tables")
	}
	var names []string
	for _, table := range tables {
		if table.Family == nftables.TableFamilyINet && strings.HasPrefix(table.Name, TraceTable) {
			names = append(names, table.Name)
		}
	}
	return names, nil
}

// ChainHooks names the hook of every base chain of the system, by "family table chain" as
// nft monitor trace writes them: "prerouting", "input", "forward", "output" or
// "postrouting". A trace tells the chain, not the hook.
func ChainHooks() (map[string]string, error) {
	conn, err := nftables.New()
	if err != nil {
		return nil, E.Cause(err, "open netlink")
	}
	chains, err := conn.ListChains()
	if err != nil {
		return nil, E.Cause(err, "list the chains")
	}
	names := map[nftables.ChainHook]string{
		*nftables.ChainHookPrerouting:  "prerouting",
		*nftables.ChainHookInput:       "input",
		*nftables.ChainHookForward:     "forward",
		*nftables.ChainHookOutput:      "output",
		*nftables.ChainHookPostrouting: "postrouting",
	}
	hooks := make(map[string]string)
	for _, chain := range chains {
		if chain.Hooknum == nil || chain.Table == nil {
			continue
		}
		if name, known := names[*chain.Hooknum]; known {
			hooks[familyName(chain.Table.Family)+" "+chain.Table.Name+" "+chain.Name] = name
		}
	}
	return hooks, nil
}
