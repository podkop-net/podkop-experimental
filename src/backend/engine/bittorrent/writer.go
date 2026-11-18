package bittorrent

import (
	"errors"
	"net/netip"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sagernet/nftables"
)

// The writer is the one goroutine that writes the set (B2's requirements, R4 and R7 of the A5
// review): a learner hands it the keys of a reply and waits at most its bound; what came while a
// write ran goes into the next one together (a group commit: one netlink batch, one wait for the
// kernel's acknowledgements). sagernet/nftables waits for those with no deadline of its own, so a
// stuck kernel holds the writer, never a reply past its bound. A write that lasts stuckAfter is
// taken as stuck: from then on the replies are not held for it, and another goroutine with a
// socket of its own takes the writes over (the one left behind ends when its write does). A panic
// of a write (the netlink library's) fails its batch, not the backend.

var (
	errLate   = errors.New("the set took longer than the wait")
	errClosed = errors.New("the module is closed")
	errNoSet  = errors.New("the set is not there")
	errFault  = errors.New("the write of the set failed with a panic")
)

// batchMost is the most requests one write takes: with at most replyMost peers a reply it stays
// far under the 65535 elements of the set (elementsPerMessage keeps each message under netlink's
// 64 KiB).
const (
	batchMost          = 64
	elementsPerMessage = 1000
)

type writeRequest struct {
	keys [][]byte
	done chan error
}

// setConn is what the writer uses of a netlink connection of nftables (a test's stands in).
type setConn interface {
	GetSetByName(table *nftables.Table, name string) (*nftables.Set, error)
	SetAddElements(set *nftables.Set, elements []nftables.SetElement) error
	Flush() error
	CloseLasting() error
}

type writer struct {
	family  nftables.TableFamily
	table   string
	name    string
	timeout time.Duration
	// closeWait is how long close waits for a write under way: the bound of the replies (wait)
	closeWait time.Duration
	// stuckAfter is how long a write may last before it is taken as stuck: ten times the bound of
	// the replies (a write of 200 peers takes 1.1 ms at p99 on oracle)
	stuckAfter time.Duration
	counters   *counters
	// open makes a netlink connection (a test's makes its own)
	open func() (setConn, error)

	requests chan *writeRequest
	stop     chan struct{}
	stopped  chan struct{}
	// busy is when the write under way began (UnixNano), 0 when none is; generation is the
	// goroutine that writes now (run); taking: a take-over is under way
	busy       atomic.Int64
	generation atomic.Int64
	taking     atomic.Bool
}

func newWriter(table string, name string, timeout time.Duration, closeWait time.Duration, counters *counters) *writer {
	return &writer{family: nftables.TableFamilyINet, table: table, name: name, timeout: timeout, closeWait: closeWait,
		stuckAfter: 10 * closeWait, counters: counters,
		open:     func() (setConn, error) { return nftables.New(nftables.AsLasting()) },
		requests: make(chan *writeRequest, batchMost), stop: make(chan struct{}), stopped: make(chan struct{})}
}

func (w *writer) start() error {
	conn, err := w.open()
	if err != nil {
		return err
	}
	go w.run(conn, w.generation.Load())
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

// add hands the writer keys and waits for them to be in the set, at most wait in all. While a
// write is stuck, nothing waits: the keys are not written.
func (w *writer) add(keys [][]byte, wait time.Duration) error {
	if began := w.busy.Load(); began != 0 && time.Since(time.Unix(0, began)) > w.stuckAfter {
		w.takeOver()
		return errLate
	}
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

// takeOver starts another goroutine, with a connection of its own, in place of the one whose write
// is stuck. Until a connection opens, add goes on answering at once.
func (w *writer) takeOver() {
	if !w.taking.CompareAndSwap(false, true) {
		return
	}
	defer w.taking.Store(false)
	select {
	case <-w.stop:
		return
	default:
	}
	if w.busy.Load() == 0 {
		// taken over meanwhile, or the write ended
		return
	}
	conn, err := w.open()
	if err != nil {
		return
	}
	w.counters.writerRestarts.Add(1)
	generation := w.generation.Add(1)
	w.busy.Store(0)
	go w.run(conn, generation)
}

// run is the writer's goroutine of a generation: it writes until the module closes, or until
// another generation took over while its write was stuck.
func (w *writer) run(conn setConn, generation int64) {
	defer func() {
		if w.generation.Load() == generation {
			close(w.stopped)
		}
	}()
	defer func() { _ = conn.CloseLasting() }()
	var set *nftables.Set
	for w.generation.Load() == generation {
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
		began := time.Now().UnixNano()
		w.busy.Store(began)
		conn, set = w.serve(conn, set, batch)
		// left alone when another generation took over meanwhile (it cleared or set it anew)
		w.busy.CompareAndSwap(began, 0)
	}
}

// serve writes a batch and answers its requests, and gives the connection and the set to go on
// with: a batch that fails for another reason than a full set is tried again, each request on its
// own, on a fresh connection (the set may have gone with its table), and so is a set that cannot
// be looked up. A panic answers what was not answered yet.
func (w *writer) serve(conn setConn, set *nftables.Set, batch []*writeRequest) (next setConn, kept *nftables.Set) {
	defer func() {
		if recover() != nil {
			w.counters.panics.Add(1)
			w.answer(batch, errFault)
			// what the connection holds of the write is not known: a fresh one, when one opens
			next, kept = conn, nil
			if fresh, err := w.open(); err == nil {
				_ = conn.CloseLasting()
				next = fresh
			}
		}
	}()
	table := &nftables.Table{Family: w.family, Name: w.table}
	if set != nil {
		err := w.write(conn, set, batch)
		if err == nil || full(err) {
			// a full set refuses each request as it refuses the batch
			w.answer(batch, err)
			return conn, set
		}
	} else if found, err := conn.GetSetByName(table, w.name); err == nil {
		// the set of the table there now: podkop makes the table anew on a change of its rules
		err = w.write(conn, found, batch)
		if err == nil || full(err) {
			w.answer(batch, err)
			return conn, found
		}
	}
	// a fresh socket, the set looked up again, then each request on its own
	fresh, err := w.open()
	if err != nil {
		w.answer(batch, err)
		return conn, nil
	}
	_ = conn.CloseLasting()
	conn = fresh
	found, err := conn.GetSetByName(table, w.name)
	if err != nil {
		w.answer(batch, errNoSet)
		return conn, nil
	}
	for _, request := range batch {
		w.answer([]*writeRequest{request}, w.write(conn, found, []*writeRequest{request}))
	}
	return conn, found
}

func (w *writer) write(conn setConn, set *nftables.Set, batch []*writeRequest) error {
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

// answer gives each request of a batch its answer, once: one answered before keeps that answer.
func (w *writer) answer(batch []*writeRequest, err error) {
	for _, request := range batch {
		select {
		case request.done <- err:
		default:
		}
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
