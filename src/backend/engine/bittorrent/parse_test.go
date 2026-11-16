package bittorrent

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

// made-up peers of the documentation ranges (RFC 5737)
var testPeers = []netip.AddrPort{
	netip.MustParseAddrPort("203.0.113.7:51413"),
	netip.MustParseAddrPort("198.51.100.20:6881"),
	netip.MustParseAddrPort("192.0.2.33:40000"),
}

func compact(peers []netip.AddrPort) []byte {
	var data []byte
	for _, peer := range peers {
		address := peer.Addr().As4()
		data = append(data, address[:]...)
		data = binary.BigEndian.AppendUint16(data, peer.Port())
	}
	return data
}

func trackerAnnounceReply(transaction uint32, peers []netip.AddrPort) []byte {
	reply := binary.BigEndian.AppendUint32(nil, trackerAnnounce)
	reply = binary.BigEndian.AppendUint32(reply, transaction)
	reply = binary.BigEndian.AppendUint32(reply, 1800)
	reply = binary.BigEndian.AppendUint32(reply, 3)
	reply = binary.BigEndian.AppendUint32(reply, 40)
	return append(reply, compact(peers)...)
}

func trackerConnectRequest(transaction uint32) []byte {
	request := binary.BigEndian.AppendUint64(nil, trackerProtocolID)
	request = binary.BigEndian.AppendUint32(request, trackerConnect)
	return binary.BigEndian.AppendUint32(request, transaction)
}

func trackerAnnounceRequest(transaction uint32) []byte {
	request := binary.BigEndian.AppendUint64(nil, 0x1122334455667788)
	request = binary.BigEndian.AppendUint32(request, trackerAnnounce)
	request = binary.BigEndian.AppendUint32(request, transaction)
	return append(request, make([]byte, trackerAnnounceLength-16)...)
}

func bstring(data []byte) string { return fmt.Sprintf("%d:%s", len(data), data) }

func dhtGetPeers(transaction string) []byte {
	return []byte("d1:ad2:id20:abcdefghij01234567899:info_hash20:mnopqrstuvwxyz123456e1:q9:get_peers1:t" + bstring([]byte(transaction)) + "1:y1:qe")
}

func dhtValues(transaction string, peers []netip.AddrPort) []byte {
	var values strings.Builder
	for _, peer := range peers {
		values.WriteString(bstring(compact([]netip.AddrPort{peer})))
	}
	return []byte("d1:rd2:id20:abcdefghij01234567895:token8:aoeusnth6:valuesl" + values.String() + "ee1:t" + bstring([]byte(transaction)) + "1:y1:re")
}

func TestTracker(t *testing.T) {
	if id, ok := trackerRequest(trackerConnectRequest(0x01020304)); !ok || id != 0x01020304 {
		t.Errorf("connect: %x %v", id, ok)
	}
	if id, ok := trackerRequest(trackerAnnounceRequest(7)); !ok || id != 7 {
		t.Errorf("announce: %x %v", id, ok)
	}
	if _, ok := trackerRequest(trackerAnnounceRequest(7)[:97]); ok {
		t.Error("a short announce is taken")
	}
	if _, ok := trackerRequest(make([]byte, 16)); ok {
		t.Error("a connect without the protocol id is taken")
	}
	id, peers, ok := trackerReply(trackerAnnounceReply(9, testPeers))
	if !ok || id != 9 || !slices.Equal(peers, testPeers) {
		t.Errorf("reply: %v %v %v", id, peers, ok)
	}
	// a trailing part shorter than a peer is left
	_, peers, _ = trackerReply(append(trackerAnnounceReply(9, testPeers), 1, 2, 3))
	if len(peers) != 3 {
		t.Errorf("trailing bytes: %v", peers)
	}
	if _, _, ok := trackerReply(append([]byte{0, 0, 0, 3}, make([]byte, 20)...)); ok {
		t.Error("an error reply (action 3) is taken")
	}
}

func TestDHT(t *testing.T) {
	if id, ok := dhtQuery(dhtGetPeers("aa")); !ok || id != "aa" {
		t.Errorf("get_peers: %q %v", id, ok)
	}
	ping := []byte("d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:bb1:y1:qe")
	if _, ok := dhtQuery(ping); ok {
		t.Error("a ping is taken for get_peers")
	}
	id, peers, ok := dhtReply(dhtValues("aa", testPeers))
	if !ok || id != "aa" || !slices.Equal(peers, testPeers) {
		t.Errorf("values: %q %v %v", id, peers, ok)
	}
	nodes := []byte("d1:rd2:id20:abcdefghij01234567895:nodes0:5:token2:xxe1:t2:aa1:y1:re")
	if id, peers, ok := dhtReply(nodes); !ok || id != "aa" || len(peers) != 0 {
		t.Errorf("nodes only: %q %v %v", id, peers, ok)
	}
	if _, _, ok := dhtReply(append(dhtValues("aa", testPeers), 'x')); ok {
		t.Error("trailing data is taken")
	}
}

func TestBencodeLimits(t *testing.T) {
	deep := strings.Repeat("l", bencodeDepth+2) + strings.Repeat("e", bencodeDepth+2)
	if _, ok := bdictionary([]byte("d1:a" + deep + "e")); ok {
		t.Error("too deep is taken")
	}
	if _, ok := bdictionary([]byte("d1:a99999:xe")); ok {
		t.Error("a string longer than the data is taken")
	}
	if _, ok := bdictionary([]byte("d1:ai12")); ok {
		t.Error("an unended integer is taken")
	}
	many := "d1:al" + strings.Repeat("i1e", bencodeItems+1) + "ee"
	if _, ok := bdictionary([]byte(many)); ok {
		t.Error("too many items are taken")
	}
}

func httpBody(peers []netip.AddrPort) []byte {
	return []byte("d8:intervali1800e5:peers" + bstring(compact(peers)) + "e")
}

func TestHTTPReply(t *testing.T) {
	body := httpBody(testPeers)
	whole := []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s", len(body), body))
	for cut := 0; cut < len(whole); cut++ {
		peers, done, err := httpReply(whole[:cut])
		if err != nil || done || peers != nil {
			t.Fatalf("cut at %d: %v %v %v", cut, peers, done, err)
		}
	}
	if peers, done, err := httpReply(whole); err != nil || !done || !slices.Equal(peers, testPeers) {
		t.Errorf("whole: %v %v %v", peers, done, err)
	}
	// without a length: whole when the body decodes whole
	open := []byte("HTTP/1.0 200 OK\r\n\r\n" + string(body))
	if peers, done, err := httpReply(open[:len(open)-1]); err != nil || done || peers != nil {
		t.Errorf("open, not whole: %v %v %v", peers, done, err)
	}
	if peers, done, err := httpReply(open); err != nil || !done || len(peers) != 3 {
		t.Errorf("open, whole: %v %v %v", peers, done, err)
	}
	// chunked
	chunked := []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n%x\r\n%s\r\n%x\r\n%s\r\n0\r\n\r\n", 10, body[:10], len(body)-10, body[10:]))
	if _, done, _ := httpReply(chunked[:len(chunked)-5]); done {
		t.Error("chunked without its last chunk is whole")
	}
	if peers, done, err := httpReply(chunked); err != nil || !done || len(peers) != 3 {
		t.Errorf("chunked: %v %v %v", peers, done, err)
	}
	// gzip
	var zipped bytes.Buffer
	writer := gzip.NewWriter(&zipped)
	_, _ = writer.Write(body)
	_ = writer.Close()
	gz := append([]byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: %d\r\n\r\n", zipped.Len())), zipped.Bytes()...)
	if peers, done, err := httpReply(gz); err != nil || !done || len(peers) != 3 {
		t.Errorf("gzip: %v %v %v", peers, done, err)
	}
	// peers as dictionaries (BEP 3)
	dicts := []byte("d5:peersld2:ip11:203.0.113.74:porti51413eed2:ip7:example4:porti1eeee")
	dictReply := append([]byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", len(dicts))), dicts...)
	if peers, done, err := httpReply(dictReply); err != nil || !done || len(peers) != 1 || peers[0] != testPeers[0] {
		t.Errorf("dictionaries: %v %v %v", peers, done, err)
	}
	if _, _, err := httpReply([]byte("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")); err == nil {
		t.Error("a 404 is read")
	}
	if _, _, err := httpReply([]byte("SSH-2.0-OpenSSH_9.6\r\n")); err == nil {
		t.Error("not HTTP is read")
	}
}

func TestMSEShaped(t *testing.T) {
	random := bytes.Repeat([]byte{0xa7, 0x13, 0x5c}, 100)
	for _, c := range []struct {
		data []byte
		want bool
	}{
		{random[:96], true},
		{random[:95], false},
		{random[:300], true},
		{bytes.Repeat([]byte{0xa7}, 609), false},
		{append([]byte{0x16, 0x03, 0x01}, random[:200]...), false},
		{append([]byte("GET /"), random[:200]...), false},
		{append([]byte("SSH-2.0-"), random[:200]...), false},
		// OpenVPN tls-crypt-v2: the length of the rest, the opcode 10 and key id 0
		{append([]byte{0, 198, 10 << 3}, random[:197]...), false},
		// WireGuard over TCP: the length 148 and the initiation
		{append([]byte{0x00, 0x94, 0x01, 0x00, 0x00, 0x00}, random[:144]...), false},
	} {
		if got := mseShaped(c.data); got != c.want {
			t.Errorf("%d bytes %x...: %v, not %v", len(c.data), c.data[:4], got, c.want)
		}
	}
}

func FuzzBencode(f *testing.F) {
	f.Add(dhtValues("aa", testPeers))
	f.Add(dhtGetPeers("zz"))
	f.Add([]byte("d1:ali1ei2eee"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = bdictionary(data)
		_, _ = dhtQuery(data)
		_, _, _ = dhtReply(data)
	})
}

func FuzzHTTPReply(f *testing.F) {
	body := httpBody(testPeers)
	f.Add([]byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body)))
	f.Add([]byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nd1:ae\r\n0\r\n\r\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = httpReply(data)
	})
}

func FuzzTracker(f *testing.F) {
	f.Add(trackerAnnounceReply(1, testPeers))
	f.Add(trackerConnectRequest(1))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = trackerRequest(data)
		_, _, _ = trackerReply(data)
		_ = isUTP(data)
	})
}
