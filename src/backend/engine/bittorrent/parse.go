package bittorrent

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"strconv"
)

// The discovery messages the learner reads: the requests a client sends, to pair each reply with
// one (R11 of the A5 review: only a reply to a request the device sent, from the address it was
// sent to, is learned), and the replies, for the peers they name.
// - a UDP tracker (BEP 15): a connect or an announce request; the announce reply (action 1);
// - the DHT (BEP 5, bencoded KRPC): a get_peers query; its answer, whose "values" are peers;
// - an HTTP tracker (BEP 3, BEP 23): the announce request on a TCP connection; its reply, whose
//   "peers" are a compact string or a list of dictionaries.

const (
	trackerProtocolID = 0x41727101980
	trackerConnect    = 0
	trackerAnnounce   = 1
	trackerScrape     = 2
	// trackerAnnounceLength is the length of an announce request of BEP 15, extensions after it
	trackerAnnounceLength = 98
)

// trackerRequest is the transaction id of a request of BEP 15: a connect (the protocol id and
// action 0) or an announce (a connection id, action 1, 98 bytes or more).
func trackerRequest(payload []byte) (uint32, bool) {
	if len(payload) < 16 {
		return 0, false
	}
	action := binary.BigEndian.Uint32(payload[8:12])
	switch {
	case action == trackerConnect && binary.BigEndian.Uint64(payload) == trackerProtocolID:
	case action == trackerAnnounce && len(payload) >= trackerAnnounceLength:
	default:
		return 0, false
	}
	return binary.BigEndian.Uint32(payload[12:16]), true
}

// discoveryMessage tells a packet of the device that is discovery but asks for no peers: a message
// of the DHT (KRPC, BEP 5: a bencoded dictionary with its type, "y"; a client may not sort its
// keys) or a scrape of a UDP tracker (BEP 15: a connection id, the action 2, a transaction id,
// then info hashes of 20 bytes each).
func discoveryMessage(payload []byte) bool {
	if len(payload) >= 36 && (len(payload)-16)%20 == 0 && binary.BigEndian.Uint32(payload[8:12]) == trackerScrape {
		return true
	}
	return len(payload) > 0 && payload[0] == 'd' && bytes.Contains(payload, []byte("1:y1:"))
}

// trackerReply is the transaction id and the peers of an announce reply of BEP 15: action 1, the
// transaction id, the interval, the leechers and the seeders, then 6 bytes a peer.
func trackerReply(payload []byte) (uint32, []netip.AddrPort, bool) {
	if len(payload) < 20 || binary.BigEndian.Uint32(payload) != trackerAnnounce {
		return 0, nil, false
	}
	return binary.BigEndian.Uint32(payload[4:8]), compactPeers(payload[20:]), true
}

// compactPeers reads peers of 6 bytes each (an IPv4 address and a port); a trailing part is left.
func compactPeers(data []byte) []netip.AddrPort {
	peers := make([]netip.AddrPort, 0, len(data)/6)
	for index := 0; index+6 <= len(data); index += 6 {
		address := netip.AddrFrom4([4]byte(data[index : index+4]))
		peers = append(peers, netip.AddrPortFrom(address, binary.BigEndian.Uint16(data[index+4:index+6])))
	}
	return peers
}

// The limits of the bencode decoder: what a discovery message holds is far below them.
const (
	bencodeDepth = 8
	bencodeItems = 8192
)

var errBencode = errors.New("not bencode")

type bvalue struct {
	str  []byte
	num  int64
	list []bvalue
	dict map[string]bvalue
	kind byte // 's', 'i', 'l', 'd'
}

// bdecode decodes one value from the front of data, with what is left after it. items counts
// the values decoded so far, against bencodeItems.
func bdecode(data []byte, depth int, items *int) (bvalue, []byte, error) {
	*items++
	if len(data) == 0 || depth > bencodeDepth || *items > bencodeItems {
		return bvalue{}, nil, errBencode
	}
	switch c := data[0]; {
	case c == 'i':
		end := bytes.IndexByte(data, 'e')
		if end < 2 {
			return bvalue{}, nil, errBencode
		}
		number, err := strconv.ParseInt(string(data[1:end]), 10, 64)
		if err != nil {
			return bvalue{}, nil, errBencode
		}
		return bvalue{kind: 'i', num: number}, data[end+1:], nil
	case c >= '0' && c <= '9':
		colon := bytes.IndexByte(data, ':')
		if colon < 1 || colon > 10 {
			return bvalue{}, nil, errBencode
		}
		length, err := strconv.Atoi(string(data[:colon]))
		if err != nil || length < 0 || length > len(data)-colon-1 {
			return bvalue{}, nil, errBencode
		}
		start := colon + 1
		return bvalue{kind: 's', str: data[start : start+length]}, data[start+length:], nil
	case c == 'l':
		value := bvalue{kind: 'l'}
		rest := data[1:]
		for {
			if len(rest) == 0 {
				return bvalue{}, nil, errBencode
			}
			if rest[0] == 'e' {
				return value, rest[1:], nil
			}
			var item bvalue
			var err error
			item, rest, err = bdecode(rest, depth+1, items)
			if err != nil {
				return bvalue{}, nil, err
			}
			value.list = append(value.list, item)
		}
	case c == 'd':
		value := bvalue{kind: 'd', dict: make(map[string]bvalue)}
		rest := data[1:]
		for {
			if len(rest) == 0 {
				return bvalue{}, nil, errBencode
			}
			if rest[0] == 'e' {
				return value, rest[1:], nil
			}
			var key, item bvalue
			var err error
			key, rest, err = bdecode(rest, depth+1, items)
			if err != nil || key.kind != 's' {
				return bvalue{}, nil, errBencode
			}
			item, rest, err = bdecode(rest, depth+1, items)
			if err != nil {
				return bvalue{}, nil, err
			}
			value.dict[string(key.str)] = item
		}
	}
	return bvalue{}, nil, errBencode
}

// bdictionary decodes data as one bencoded dictionary and nothing after it.
func bdictionary(data []byte) (map[string]bvalue, bool) {
	if len(data) == 0 || data[0] != 'd' {
		return nil, false
	}
	items := 0
	value, rest, err := bdecode(data, 0, &items)
	if err != nil || len(rest) != 0 {
		return nil, false
	}
	return value.dict, true
}

func (v bvalue) text(key string) (string, bool) {
	item, ok := v.dict[key]
	if !ok || item.kind != 's' {
		return "", false
	}
	return string(item.str), true
}

// dhtQuery is the transaction id of a get_peers query of the DHT: the only query whose answer
// names peers.
func dhtQuery(payload []byte) (string, bool) {
	dict, ok := bdictionary(payload)
	if !ok {
		return "", false
	}
	message := bvalue{kind: 'd', dict: dict}
	if kind, _ := message.text("y"); kind != "q" {
		return "", false
	}
	if query, _ := message.text("q"); query != "get_peers" {
		return "", false
	}
	transaction, ok := message.text("t")
	return transaction, ok && transaction != ""
}

// dhtReply is the transaction id and the peers of an answer of the DHT: "values" of its "r", the
// peers of 6 bytes (the IPv4 DHT; those of 18 bytes, BEP 32, are of IPv6, which podkop's
// firewall does not handle).
func dhtReply(payload []byte) (string, []netip.AddrPort, bool) {
	dict, ok := bdictionary(payload)
	if !ok {
		return "", nil, false
	}
	message := bvalue{kind: 'd', dict: dict}
	if kind, _ := message.text("y"); kind != "r" {
		return "", nil, false
	}
	transaction, ok := message.text("t")
	if !ok {
		return "", nil, false
	}
	answer, ok := dict["r"]
	if !ok || answer.kind != 'd' {
		return transaction, nil, true
	}
	values, ok := answer.dict["values"]
	if !ok || values.kind != 'l' {
		return transaction, nil, true
	}
	var peers []netip.AddrPort
	for _, value := range values.list {
		if value.kind == 's' && len(value.str) == 6 {
			peers = append(peers, compactPeers(value.str)...)
		}
	}
	return transaction, peers, true
}

// httpAnnounce tells the first data of a connection that is an announce to an HTTP tracker, as
// the firewall's signature does (GET /announce? or GET /announce.php?).
func httpAnnounce(data []byte) bool {
	return bytes.HasPrefix(data, []byte("GET /announce?")) || bytes.HasPrefix(data, []byte("GET /announce.php?"))
}

// httpReplyLimit is the most of a tracker's reply the learner keeps: a reply of 200 compact peers
// is about 1.3 KB, of 200 peers as dictionaries about 12 KB.
const httpReplyLimit = 256 << 10

var errHTTPReply = errors.New("not a tracker reply")

// httpReply reads the reply of an HTTP tracker as far as it came: done when it is whole (by its
// length, its last chunk, or a body that decodes whole), with its peers; an error when it is not
// a reply of 200 with a bencoded body, or is longer than httpReplyLimit.
func httpReply(data []byte) (peers []netip.AddrPort, done bool, err error) {
	if len(data) > httpReplyLimit {
		return nil, false, errHTTPReply
	}
	end := bytes.Index(data, []byte("\r\n\r\n"))
	if end < 0 {
		if len(data) >= 12 && !bytes.HasPrefix(data, []byte("HTTP/1.")) {
			return nil, false, errHTTPReply
		}
		return nil, false, nil
	}
	lines := bytes.Split(data[:end], []byte("\r\n"))
	status := bytes.Fields(lines[0])
	if len(status) < 2 || !bytes.HasPrefix(status[0], []byte("HTTP/1.")) || string(status[1]) != "200" {
		return nil, false, errHTTPReply
	}
	length := -1
	var chunked bool
	var encoding string
	for _, line := range lines[1:] {
		colon := bytes.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		name := string(bytes.ToLower(bytes.TrimSpace(line[:colon])))
		value := string(bytes.ToLower(bytes.TrimSpace(line[colon+1:])))
		switch name {
		case "content-length":
			if number, err := strconv.Atoi(value); err == nil && number >= 0 {
				length = number
			}
		case "transfer-encoding":
			chunked = value == "chunked"
		case "content-encoding":
			encoding = value
		}
	}
	body := data[end+4:]
	// the reply is read again at each write that brings more of it: a part that cannot be its end
	// is let go at once (a chunked body ends with a line, a bencoded one with "e")
	switch {
	case chunked:
		if !bytes.HasSuffix(body, []byte("\r\n")) {
			return nil, false, nil
		}
		var whole bool
		body, whole = dechunk(body)
		if !whole {
			return nil, false, nil
		}
	case length >= 0:
		if len(body) < length {
			return nil, false, nil
		}
		body = body[:length]
	}
	switch encoding {
	case "", "identity":
		if !chunked && length < 0 && !bytes.HasSuffix(bytes.TrimRight(body, " \t\r\n"), []byte("e")) {
			return nil, false, nil
		}
	case "gzip", "x-gzip", "deflate":
		decoded, err := inflate(body, encoding)
		if err != nil {
			// a body without its length that does not inflate yet may not have come whole
			if !chunked && length < 0 {
				return nil, false, nil
			}
			return nil, false, errHTTPReply
		}
		body = decoded
	default:
		return nil, false, errHTTPReply
	}
	dict, ok := bdictionary(bytes.TrimRight(body, " \t\r\n"))
	if !ok {
		if !chunked && length < 0 {
			return nil, false, nil
		}
		return nil, false, errHTTPReply
	}
	return httpPeers(dict), true, nil
}

// httpPeers are the peers of a tracker's reply: a compact string (BEP 23) or a list of
// dictionaries with "ip" and "port" (BEP 3).
func httpPeers(dict map[string]bvalue) []netip.AddrPort {
	value, ok := dict["peers"]
	if !ok {
		return nil
	}
	switch value.kind {
	case 's':
		return compactPeers(value.str)
	case 'l':
		var peers []netip.AddrPort
		for _, item := range value.list {
			if item.kind != 'd' {
				continue
			}
			text, _ := item.text("ip")
			port, ok := item.dict["port"]
			if !ok || port.kind != 'i' || port.num < 1 || port.num > 65535 {
				continue
			}
			address, err := netip.ParseAddr(text)
			if err != nil || !address.Is4() {
				continue
			}
			peers = append(peers, netip.AddrPortFrom(address, uint16(port.num)))
		}
		return peers
	}
	return nil
}

// dechunk is the body of chunked transfer coding as far as it came, and whether its last chunk
// has come.
func dechunk(data []byte) ([]byte, bool) {
	var body []byte
	for {
		line := bytes.Index(data, []byte("\r\n"))
		if line < 0 {
			return body, false
		}
		sizeText := data[:line]
		if semicolon := bytes.IndexByte(sizeText, ';'); semicolon >= 0 {
			sizeText = sizeText[:semicolon]
		}
		size, err := strconv.ParseInt(string(bytes.TrimSpace(sizeText)), 16, 32)
		if err != nil || size < 0 {
			return body, false
		}
		data = data[line+2:]
		if size == 0 {
			return body, true
		}
		if int64(len(data)) < size+2 {
			return body, false
		}
		body = append(body, data[:size]...)
		data = data[size+2:]
	}
}

// inflate decodes a body of gzip or deflate (zlib, or raw deflate as some servers send it), up to
// httpReplyLimit.
func inflate(body []byte, encoding string) ([]byte, error) {
	var reader io.Reader
	switch encoding {
	case "gzip", "x-gzip":
		gz, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		reader = gz
	default:
		z, err := zlib.NewReader(bytes.NewReader(body))
		if err != nil {
			reader = flate.NewReader(bytes.NewReader(body))
		} else {
			reader = z
		}
	}
	decoded, err := io.ReadAll(io.LimitReader(reader, httpReplyLimit+1))
	if err != nil {
		return nil, err
	}
	if len(decoded) > httpReplyLimit {
		return nil, errHTTPReply
	}
	return decoded, nil
}
