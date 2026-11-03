// Package ubus speaks the protocol of ubusd, the message bus of OpenWrt, so that the backend
// publishes an object of its own: LuCI calls its methods through uhttpd's /ubus (JSON-RPC,
// with the access lists of rpcd), and the backend that runs answers them itself, with no
// program started for a call. Only what that needs is here: the hello of ubusd, the object
// added with the signature of its methods, and the answers to the calls. The messages are
// those of libubus (ubusmsg.h) on the unix socket of ubusd, each a header and a blob of
// libubox (blob.go).
package ubus

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"os"
	"sort"
	"sync"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

// SocketPaths are where ubusd listens: OpenWrt since 21.02, then before.
var SocketPaths = []string{"/var/run/ubus/ubus.sock", "/var/run/ubus.sock"}

// The statuses of an answer (enum ubus_msg_status); ubus and uhttpd tell them by name.
const (
	StatusOK               = 0
	StatusInvalidCommand   = 1
	StatusInvalidArgument  = 2
	StatusMethodNotFound   = 3
	StatusNotFound         = 4
	StatusNoData           = 5
	StatusPermissionDenied = 6
	StatusTimeout          = 7
	StatusNotSupported     = 8
	StatusUnknownError     = 9
)

// the types of messages
const (
	messageHello     = 0
	messageStatus    = 1
	messageData      = 2
	messageInvoke    = 5
	messageAddObject = 6
)

// the attributes of a message
const (
	attributeStatus    = 1
	attributeObjPath   = 2
	attributeObjID     = 3
	attributeMethod    = 4
	attributeSignature = 6
	attributeData      = 7
	attributeNoReply   = 10
)

// a message is a header of 8 bytes (version, type, sequence number, peer: big-endian) and
// one blob attribute that holds the attributes of the message; ubusd takes no more than a
// few megabytes
const (
	messageHeader = 8
	messageLimit  = 64 << 20
)

// calls answered at once; more wait for one of them to end
const concurrentCalls = 8

// A Method answers a call of the object.
type Method struct {
	// Arguments names the arguments and their types (TypeString, TypeInt32, TypeBool…): the
	// signature of the method, what "ubus -v list" shows. A call may still send others.
	Arguments map[string]int
	// Call answers with the arguments read from the call (a table: maps, slices, strings,
	// int64, float64, bool) and returns what encoding/json writes as an object, or a status
	// other than StatusOK. It runs while the call waits: LuCI gives up after 20 s.
	Call func(ctx context.Context, arguments map[string]any) (any, int)
}

// Object is what Serve publishes.
type Object struct {
	Name    string
	Methods map[string]Method
}

type message struct {
	kind  int
	seq   uint16
	peer  uint32
	attrs map[int]attr
}

func readMessage(reader io.Reader) (*message, error) {
	var head [messageHeader + attrHeader]byte
	if _, err := io.ReadFull(reader, head[:]); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint32(head[messageHeader:]) & attrLenMask)
	if length < attrHeader || length > messageLimit {
		return nil, E.New("a message of ", length, " bytes")
	}
	payload := make([]byte, length-attrHeader)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return nil, err
	}
	attrs, err := readAttrs(payload)
	if err != nil {
		return nil, err
	}
	result := &message{
		kind:  int(head[1]),
		seq:   binary.BigEndian.Uint16(head[2:]),
		peer:  binary.BigEndian.Uint32(head[4:]),
		attrs: make(map[int]attr, len(attrs)),
	}
	for _, item := range attrs {
		result.attrs[item.id] = item
	}
	return result, nil
}

// encodeMessage puts the header before the attributes that fill writes.
func encodeMessage(kind int, seq uint16, peer uint32, fill func(w *writer) error) ([]byte, error) {
	w := &writer{buffer: make([]byte, messageHeader, 256)}
	w.buffer[0] = 0
	w.buffer[1] = byte(kind)
	binary.BigEndian.PutUint16(w.buffer[2:], seq)
	binary.BigEndian.PutUint32(w.buffer[4:], peer)
	at := w.open(0, false)
	if err := fill(w); err != nil {
		return nil, err
	}
	w.close(at)
	return w.buffer, nil
}

func (m *message) uint32(id int) (uint32, bool) {
	item, found := m.attrs[id]
	if !found || len(item.payload) < 4 {
		return 0, false
	}
	return binary.BigEndian.Uint32(item.payload), true
}

func (m *message) string(id int) (string, bool) {
	item, found := m.attrs[id]
	if !found || len(item.payload) == 0 || item.payload[len(item.payload)-1] != 0 {
		return "", false
	}
	return string(item.payload[:len(item.payload)-1]), true
}

// Serve publishes the object on the bus at path and answers its calls until the context
// ends. A connection lost (ubusd restarted) is made again after a pause that grows to half a
// minute; say tells why, at most once a minute.
func Serve(ctx context.Context, path string, object Object, say func(message string)) {
	pause := time.Second
	var told time.Time
	for ctx.Err() == nil {
		started := time.Now()
		err := serveOnce(ctx, path, object)
		if ctx.Err() != nil {
			return
		}
		if time.Since(started) > time.Minute {
			pause = time.Second
		}
		if time.Since(told) > time.Minute {
			say("the object " + object.Name + " of ubus is not there: " + err.Error())
			told = time.Now()
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(pause):
		}
		pause = min(pause*2, 30*time.Second)
	}
}

func serveOnce(ctx context.Context, path string, object Object) error {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "unix", path)
	if err != nil {
		return err
	}
	defer conn.Close()
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-stop:
		}
	}()

	hello, err := readMessage(conn)
	if err != nil {
		return E.Cause(err, "hello of ubusd")
	}
	if hello.kind != messageHello {
		return E.New("ubusd said ", hello.kind, " for hello")
	}

	request, err := encodeMessage(messageAddObject, 1, 0, func(w *writer) error {
		w.putString(attributeObjPath, object.Name)
		signature := w.open(attributeSignature, false)
		names := make([]string, 0, len(object.Methods))
		for name := range object.Methods {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			table := w.openNamed(TypeTable, name)
			arguments := object.Methods[name].Arguments
			keys := make([]string, 0, len(arguments))
			for key := range arguments {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				field := w.openNamed(TypeInt32, key)
				w.buffer = binary.BigEndian.AppendUint32(w.buffer, uint32(arguments[key]))
				w.close(field)
			}
			w.close(table)
		}
		w.close(signature)
		return nil
	})
	if err != nil {
		return err
	}
	if _, err = conn.Write(request); err != nil {
		return err
	}
	var objectID uint32
	for {
		answer, err := readMessage(conn)
		if err != nil {
			return E.Cause(err, "answer of ubusd to the object")
		}
		if answer.seq != 1 {
			continue
		}
		if answer.kind == messageData {
			objectID, _ = answer.uint32(attributeObjID)
			continue
		}
		if answer.kind == messageStatus {
			status, _ := answer.uint32(attributeStatus)
			if status != StatusOK {
				return E.New("ubusd refused the object ", object.Name, ": status ", status)
			}
			break
		}
	}
	if objectID == 0 {
		return E.New("ubusd gave no id to the object ", object.Name)
	}

	var writing sync.Mutex
	send := func(data []byte) {
		writing.Lock()
		defer writing.Unlock()
		_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		_, _ = conn.Write(data)
	}
	calls := make(chan struct{}, concurrentCalls)
	var running sync.WaitGroup
	defer running.Wait()
	for {
		call, err := readMessage(conn)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if call.kind != messageInvoke {
			continue
		}
		select {
		case calls <- struct{}{}:
		case <-ctx.Done():
			return nil
		}
		running.Add(1)
		go func() {
			defer running.Done()
			defer func() { <-calls }()
			answer(ctx, object, objectID, call, send)
		}()
	}
}

// answer runs the method a call names and sends its answer: the data, then the status.
func answer(ctx context.Context, object Object, objectID uint32, call *message, send func([]byte)) {
	method, _ := call.string(attributeMethod)
	status := StatusOK
	var reply map[string]any
	if target, _ := call.uint32(attributeObjID); target != objectID {
		status = StatusNotFound
	} else if handler, found := object.Methods[method]; !found {
		status = StatusMethodNotFound
	} else {
		arguments := map[string]any{}
		if data, found := call.attrs[attributeData]; found {
			var err error
			arguments, err = readTable(data.payload)
			if err != nil {
				status = StatusInvalidArgument
			}
		}
		if status == StatusOK {
			result, code := handler.Call(ctx, arguments)
			status = code
			if status == StatusOK {
				reply, status = AsTable(result)
			}
		}
	}
	if _, noReply := call.attrs[attributeNoReply]; noReply {
		return
	}
	if status == StatusOK {
		data, err := encodeMessage(messageData, call.seq, call.peer, func(w *writer) error {
			w.putInt32(attributeObjID, objectID)
			at := w.open(attributeData, false)
			keys := make([]string, 0, len(reply))
			for key := range reply {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				if err := w.putValue(key, reply[key]); err != nil {
					return err
				}
			}
			w.close(at)
			return nil
		})
		if err != nil {
			status = StatusUnknownError
		} else {
			send(data)
		}
	}
	done, _ := encodeMessage(messageStatus, call.seq, call.peer, func(w *writer) error {
		w.putInt32(attributeStatus, uint32(status))
		w.putInt32(attributeObjID, objectID)
		return nil
	})
	send(done)
}

// AsTable gives what a method returned in the generic form of encoding/json, numbers kept
// exact, as the call of the method answers it; an answer that is not an object is the method's
// mistake.
func AsTable(result any) (map[string]any, int) {
	encoded, err := json.Marshal(result)
	if err != nil {
		return nil, StatusUnknownError
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var table map[string]any
	if err := decoder.Decode(&table); err != nil || table == nil {
		return nil, StatusUnknownError
	}
	return table, StatusOK
}

// Socket returns the first of SocketPaths that is there, or the first of them.
func Socket() string {
	for _, path := range SocketPaths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return SocketPaths[0]
}
