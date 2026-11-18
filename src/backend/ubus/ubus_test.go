package ubus

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var testObject = Object{
	Name: "podkop-ubustest",
	Methods: map[string]Method{
		"echo": {
			Arguments: map[string]int{"text": TypeString, "number": TypeInt32},
			Call: func(ctx context.Context, arguments map[string]any) (any, int) {
				return map[string]any{"got": arguments, "kinds": []any{"a", 1, 2.5, true, int64(5000000000)}}, StatusOK
			},
		},
		"missing": {
			Call: func(ctx context.Context, arguments map[string]any) (any, int) {
				return nil, StatusNotFound
			},
		},
		"slow": {
			Call: func(ctx context.Context, arguments map[string]any) (any, int) {
				time.Sleep(300 * time.Millisecond)
				return struct {
					Done bool `json:"done"`
				}{true}, StatusOK
			},
		},
		"list": {
			Call: func(ctx context.Context, arguments map[string]any) (any, int) {
				return []string{"not", "an", "object"}, StatusOK
			},
		},
		// a method that panics: the call fails, the object goes on serving
		"faulty": {
			Call: func(ctx context.Context, arguments map[string]any) (any, int) {
				var none map[string]int
				none["fault"] = 1
				return nil, StatusOK
			},
		},
	},
}

// a stand-in for ubusd: the hello, the answer to the object, then the calls of the test
func TestServeWithStandIn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ubus.sock")
	listener, err := net.Listen("unix", path)
	require.NoError(t, err)
	defer listener.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	served := make(chan struct{})
	go func() {
		Serve(ctx, path, testObject, func(message string) { t.Log(message) })
		close(served)
	}()

	conn, err := listener.Accept()
	require.NoError(t, err)
	defer conn.Close()
	send := func(kind int, seq uint16, peer uint32, fill func(w *writer) error) {
		data, err := encodeMessage(kind, seq, peer, fill)
		require.NoError(t, err)
		_, err = conn.Write(data)
		require.NoError(t, err)
	}
	send(messageHello, 0, 0x1234, func(w *writer) error { return nil })

	add, err := readMessage(conn)
	require.NoError(t, err)
	require.Equal(t, messageAddObject, add.kind)
	name, _ := add.string(attributeObjPath)
	require.Equal(t, "podkop-ubustest", name)
	signature, err := readTable(add.attrs[attributeSignature].payload)
	require.NoError(t, err)
	require.Equal(t, map[string]any{"text": int64(TypeString), "number": int64(TypeInt32)}, signature["echo"])
	require.Equal(t, map[string]any{}, signature["missing"])

	const objectID = 0xabc
	send(messageData, add.seq, 0, func(w *writer) error { w.putInt32(attributeObjID, objectID); return nil })
	send(messageStatus, add.seq, 0, func(w *writer) error { w.putInt32(attributeStatus, StatusOK); return nil })

	invoke := func(seq uint16, method string, arguments map[string]any) {
		send(messageInvoke, seq, 0x55, func(w *writer) error {
			w.putInt32(attributeObjID, objectID)
			w.putString(attributeMethod, method)
			at := w.open(attributeData, false)
			for key, value := range arguments {
				if err := w.putValue(key, value); err != nil {
					return err
				}
			}
			w.close(at)
			return nil
		})
	}
	// the answers of a call: its data, if any, and its status
	answers := func() map[uint16][]*message {
		got := map[uint16][]*message{}
		for {
			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			reply, err := readMessage(conn)
			require.NoError(t, err)
			require.Equal(t, uint32(0x55), reply.peer)
			got[reply.seq] = append(got[reply.seq], reply)
			if reply.kind == messageStatus {
				return got
			}
		}
	}

	invoke(7, "echo", map[string]any{"text": "hi"})
	got := answers()[7]
	require.Len(t, got, 2)
	require.Equal(t, messageData, got[0].kind)
	id, _ := got[0].uint32(attributeObjID)
	require.Equal(t, uint32(objectID), id)
	data, err := readTable(got[0].attrs[attributeData].payload)
	require.NoError(t, err)
	require.Equal(t, map[string]any{"text": "hi"}, data["got"])
	require.Equal(t, []any{"a", int64(1), 2.5, true, int64(5000000000)}, data["kinds"])
	status, _ := got[1].uint32(attributeStatus)
	require.Equal(t, uint32(StatusOK), status)

	for _, c := range []struct {
		method string
		status uint32
	}{{"nothing", StatusMethodNotFound}, {"missing", StatusNotFound}, {"list", StatusUnknownError}, {"faulty", StatusUnknownError}, {"missing", StatusNotFound}} {
		invoke(8, c.method, nil)
		got = answers()[8]
		require.Len(t, got, 1, c.method)
		status, _ = got[0].uint32(attributeStatus)
		require.Equal(t, c.status, status, c.method)
	}

	cancel()
	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not end with its context")
	}
}

// the object that ubusd refuses: Serve tries again, and says why once
func TestServeRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ubus.sock")
	listener, err := net.Listen("unix", path)
	require.NoError(t, err)
	defer listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var said []string
	var lock sync.Mutex
	go Serve(ctx, path, testObject, func(message string) {
		lock.Lock()
		said = append(said, message)
		lock.Unlock()
	})
	for attempt := 0; attempt < 2; attempt++ {
		conn, err := listener.Accept()
		require.NoError(t, err)
		data, _ := encodeMessage(messageHello, 0, 1, func(w *writer) error { return nil })
		_, _ = conn.Write(data)
		add, err := readMessage(conn)
		require.NoError(t, err)
		data, _ = encodeMessage(messageStatus, add.seq, 0, func(w *writer) error {
			w.putInt32(attributeStatus, StatusPermissionDenied)
			return nil
		})
		_, _ = conn.Write(data)
		conn.Close()
	}
	lock.Lock()
	defer lock.Unlock()
	require.Len(t, said, 1)
	require.Contains(t, said[0], "status 6")
}

// The real ubusd and its command line (on OpenWrt: UBUS_REAL=/var/run/ubus/ubus.sock): the
// object is listed with its signature, and calls get the answers the methods give.
func TestServeWithUbusd(t *testing.T) {
	path := os.Getenv("UBUS_REAL")
	if path == "" {
		t.Skip("UBUS_REAL is not set")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go Serve(ctx, path, testObject, func(message string) { t.Log(message) })
	ubus := func(arguments ...string) (string, error) {
		output, err := exec.Command("ubus", arguments...).CombinedOutput()
		return strings.TrimSpace(string(output)), err
	}
	require.Eventually(t, func() bool {
		_, err := ubus("list", "podkop-ubustest")
		return err == nil
	}, 5*time.Second, 50*time.Millisecond)

	listed, err := ubus("-v", "list", "podkop-ubustest")
	require.NoError(t, err)
	t.Log(listed)
	require.Contains(t, listed, `"echo":{"number":"Integer","text":"String"}`)

	output, err := ubus("call", "podkop-ubustest", "echo", `{"text":"hi","number":5,"yes":true,"big":5000000000,"f":1.5,"t":{"k":[1,"two",false]}}`)
	require.NoError(t, err, output)
	require.JSONEq(t, `{"got":{"text":"hi","number":5,"yes":true,"big":5000000000,"f":1.5,"t":{"k":[1,"two",false]}},
		"kinds":["a",1,2.5,true,5000000000]}`, output)

	output, err = ubus("call", "podkop-ubustest", "missing")
	require.Error(t, err)
	require.Contains(t, output, "Not found")
	output, err = ubus("call", "podkop-ubustest", "nothing")
	require.Error(t, err)
	require.Contains(t, output, "Method not found")

	// calls at once: the slow ones do not hold the others back beyond the limit
	started := time.Now()
	var group sync.WaitGroup
	failures := make(chan string, 16)
	for i := 0; i < 16; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			if output, err := ubus("call", "podkop-ubustest", "slow"); err != nil || !strings.Contains(output, `"done": true`) {
				failures <- output
			}
		}()
	}
	group.Wait()
	close(failures)
	for failure := range failures {
		t.Error("slow:", failure)
	}
	t.Log("16 slow calls in", time.Since(started))
	require.Less(t, time.Since(started), 3*time.Second)
}
