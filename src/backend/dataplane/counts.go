package dataplane

// What the kernel counts of the traffic the BitTorrent detector of the firewall marked: the
// firewall reads it (firewall.BitTorrentFlows, firewall.BitTorrentDrops), the statistics add it
// up (btstats, which names these types its own).

// Count is packets and bytes.
type Count struct {
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

// Add adds what other counted.
func (c *Count) Add(other Count) {
	c.Packets += other.Packets
	c.Bytes += other.Bytes
}

// Flow is a conntrack entry with a mark of the detector (the bits of the conntrack mark of this
// package: BitTorrentCt and the others), as the kernel counts it: Original is the way of the
// packet that began the connection, Reply the other.
type Flow struct {
	ID uint32
	// Key tells an entry from another that took the same ID after it (its tuple)
	Key      string
	UDP      bool
	Mark     uint32
	Incoming bool // its destination was rewritten (a port forward)
	Counted  bool // the kernel counts it (accounting on)
	Original Count
	Reply    Count
}

// Drops are the counters of the firewall's rules that drop BitTorrent: by the kind of what they
// dropped, a new connection from outside to a client's socket (the mode block), and the uTP SYNs
// on a flow of discovery the firewall drops so that the client goes to the peer over TCP. And the
// counters of what the detector could not take: the packets whose device, socket, peer or uTP
// socket a set had no room for (Full*), and those it did not look at because their source address
// is not of the interface they came in on (Foreign).
type Drops struct {
	Discovery, UTP, TCP                        Count
	Incoming                                   Count
	UTPToTCP                                   Count
	FullHosts, FullSockets, FullPeers, FullUTP Count
	Foreign                                    Count
}
