package bittorrent

import (
	"errors"
	"net/netip"
	"syscall"
	"time"

	"github.com/sagernet/nftables"
)

// The writer is the one goroutine that writes the set (B2's requirements, R4 and R7 of the A5
// review): a learner hands it the keys of a reply and waits at most its bound; what came while a
// write ran goes into the next one together (a group commit: one netlink batch, one wait for the
// kernel's acknowledgements). sagernet/nftables waits for those with no deadline of its own, so a
// stuck kernel holds the writer, never a reply past its bound.

var (
	errLate   = errors.New("the set took longer than the wait")
	errClosed = errors.New("the module is closed")
	errNoSet  = errors.New("the set is not there")
)

// batchMost is the most requests one write takes: with 200 peers a reply it stays far under the
// 65535 elements of the set (elementsPerMessage keeps each message under netlink's 64 KiB).
const (
	batchMost          = 64
	elementsPerMessage = 1000
)

type writeRequest struct {
	keys [][]byte
	done chan error
}

type writer struct {
	family  nftables.TableFamily
	table   string
	name    string
	timeout time.Duration
	// closeWait is how long close waits for a write under way: the bound of the replies (wait)
	closeWait time.Duration
	counters  *counters

	requests chan *writeRequest
	stop     chan struct{}
	stopped  chan struct{}
}

func newWriter(table string, name string, timeout time.Duration, closeWait time.Duration, counters *counters) *writer {
	return &writer{family: nftables.TableFamilyINet, table: table, name: name, timeout: timeout, closeWait: closeWait,
		counters: counters, requests: make(chan *writeRequest, batchMost), stop: make(chan struct{}), stopped: make(chan struct{})}
}

func (w *writer) start() error {
	conn, err := nftables.New(nftables.AsLasting())
	if err != nil {
		return err
	}
	go w.run(conn)
	return nil
}

// close stops the writer; a write the kernel never answers is left behind after closeWait (the
// replies' own bound, Options.Wait: a write of 200 peers takes 1.1 ms at p99 on oracle), so that
// the box closes (sagernet/nftables waits for its acknowledgements with no deadline).
func (w *writer) close() {
	close(w.stop)
	select {
	case <-w.stopped:
	case <-time.After(w.closeWait):
	}
}

// add hands the writer keys and waits for them to be in the set, at most wait in all.
func (w *writer) add(keys [][]byte, wait time.Duration) error {
	request := &writeRequest{keys: keys, done: make(chan error, 1)}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case w.requests <- request:
	case <-timer.C:
		return errLate
	case <-w.stop:
		return errClosed
	}
	select {
	case err := <-request.done:
		return err
	case <-timer.C:
		return errLate
	}
}

func (w *writer) run(conn *nftables.Conn) {
	defer close(w.stopped)
	defer func() { _ = conn.CloseLasting() }()
	var set *nftables.Set
	for {
		var batch []*writeRequest
		select {
		case request := <-w.requests:
			batch = append(batch, request)
		case <-w.stop:
			return
		}
	gather:
		for len(batch) < batchMost {
			select {
			case request := <-w.requests:
				batch = append(batch, request)
			default:
				break gather
			}
		}
		if set == nil {
			// the set of the table there now: podkop makes the table anew on a change of its rules
			found, err := conn.GetSetByName(&nftables.Table{Family: w.family, Name: w.table}, w.name)
			if err != nil {
				w.answer(batch, errNoSet)
				continue
			}
			set = found
		}
		err := w.write(conn, set, batch)
		if err == nil || full(err) {
			// a full set refuses each request as it refuses the batch
			w.answer(batch, err)
			continue
		}
		// a batch fails whole: the set may have gone with its table (look it up again); a fresh
		// socket, then each request on its own
		set = nil
		_ = conn.CloseLasting()
		fresh, openErr := nftables.New(nftables.AsLasting())
		if openErr != nil {
			w.answer(batch, openErr)
			continue
		}
		conn = fresh
		found, lookupErr := conn.GetSetByName(&nftables.Table{Family: w.family, Name: w.table}, w.name)
		if lookupErr != nil {
			w.answer(batch, errNoSet)
			continue
		}
		set = found
		for _, request := range batch {
			request.done <- w.write(conn, set, []*writeRequest{request})
		}
	}
}

func (w *writer) write(conn *nftables.Conn, set *nftables.Set, batch []*writeRequest) error {
	var elements []nftables.SetElement
	for _, request := range batch {
		for _, key := range request.keys {
			elements = append(elements, nftables.SetElement{Key: key, Timeout: w.timeout})
		}
	}
	for len(elements) > 0 {
		count := min(elementsPerMessage, len(elements))
		if err := conn.SetAddElements(set, elements[:count]); err != nil {
			return err
		}
		elements = elements[count:]
	}
	err := conn.Flush()
	if full(err) {
		w.counters.setFull.Add(1)
	}
	return err
}

// full tells the kernel's answer to elements a set has no room for.
func full(err error) bool {
	return err != nil && (errors.Is(err, syscall.ENFILE) || errors.Is(err, syscall.ENOSPC))
}

func (w *writer) answer(batch []*writeRequest, err error) {
	for _, request := range batch {
		request.done <- err
	}
}

// readHosts reads the set of devices (ipv4_addr) of the table of the family inet: the early check's
// look-up of the devices known to run a client.
func readHosts(table string, name string) (map[netip.Addr]bool, error) {
	conn, err := nftables.New()
	if err != nil {
		return nil, err
	}
	set, err := conn.GetSetByName(&nftables.Table{Name: table, Family: nftables.TableFamilyINet}, name)
	if err != nil {
		return nil, err
	}
	elements, err := conn.GetSetElements(set)
	if err != nil {
		return nil, err
	}
	known := make(map[netip.Addr]bool, len(elements))
	for _, element := range elements {
		if address, ok := netip.AddrFromSlice(element.Key); ok {
			known[address.Unmap()] = true
		}
	}
	return known, nil
}
