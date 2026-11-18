package engine

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/podkop-net/podkop-experimental/src/backend/detect"
	"github.com/stretchr/testify/require"
)

// answering gives a connection whose far side reads the request and then writes what answer gives
// it, until the connection closes.
func answering(t *testing.T, answer func(far net.Conn)) net.Conn {
	t.Helper()
	near, far := net.Pipe()
	t.Cleanup(func() { near.Close(); far.Close() })
	go func() {
		buffer := make([]byte, 4096)
		for read := 0; read < 4; {
			n, err := far.Read(buffer)
			if err != nil {
				return
			}
			// to the end of the request's headers
			if n >= 4 && string(buffer[n-4:n]) == "\r\n\r\n" {
				break
			}
			read++
		}
		answer(far)
	}()
	return near
}

// A far side that sends bytes with no end of line, as a status line or as a header, is read up to
// probeHeaderLimit and no further: http.ReadResponse keeps a line whole, and the flows of a burst
// grew until their deadline (the review of 0.8.18).
func TestExchangeBoundsHeaders(t *testing.T) {
	t.Parallel()
	for name, start := range map[string]string{"a status line": "", "a header": "HTTP/1.1 200 OK\r\nX-Fill: "} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			conn := answering(t, func(far net.Conn) {
				_, _ = far.Write([]byte(start))
				fill := make([]byte, 16<<10)
				for i := range fill {
					fill[i] = 'a'
				}
				for {
					if _, err := far.Write(fill); err != nil {
						return
					}
				}
			})
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			began := time.Now()
			attempt := exchange(ctx, conn, "http://probe.test/")
			require.Less(t, time.Since(began), 10*time.Second, "the headers were read to the deadline")
			require.Equal(t, detect.ClassOther, attempt.Class)
			require.LessOrEqual(t, attempt.Bytes, int64(probeHeaderLimit))
			require.GreaterOrEqual(t, attempt.Bytes, int64(probeHeaderLimit-4096))
		})
	}
}

// A body with no end is read up to probeReadLimit, and the answer is not read after that: closing
// the body of http.ReadResponse reads all of it when the answer does not say it closes.
func TestExchangeLeavesAnEndlessBody(t *testing.T) {
	t.Parallel()
	conn := answering(t, func(far net.Conn) {
		_, _ = far.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 1099511627776\r\n\r\n"))
		fill := make([]byte, 64<<10)
		for {
			if _, err := far.Write(fill); err != nil {
				return
			}
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	began := time.Now()
	attempt := exchange(ctx, conn, "http://probe.test/")
	require.Less(t, time.Since(began), 10*time.Second, "the body was read to the deadline")
	require.Equal(t, 200, attempt.Status)
	require.Equal(t, detect.ClassNone, attempt.Class)
	require.GreaterOrEqual(t, attempt.Bytes, int64(probeReadLimit))
	require.LessOrEqual(t, attempt.Bytes, int64(probeReadLimit+probeHeaderLimit))
}

// An answer of the usual kind is read whole, as before.
func TestExchangeReadsAnAnswer(t *testing.T) {
	t.Parallel()
	body := make([]byte, 64000)
	conn := answering(t, func(far net.Conn) {
		_, _ = far.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 64000\r\nConnection: close\r\n\r\n"))
		_, _ = far.Write(body)
		_, _ = io.Copy(io.Discard, far)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	attempt := exchange(ctx, conn, "http://probe.test/")
	require.Equal(t, 200, attempt.Status)
	require.Equal(t, detect.ClassNone, attempt.Class)
	require.Greater(t, attempt.Bytes, int64(64000))
	require.Less(t, attempt.Bytes, int64(64000+200))
}
