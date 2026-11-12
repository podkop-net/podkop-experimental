package engine

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/podkop-net/podkop-experimental/src/backend/detect"
	"github.com/sagernet/sing-box/adapter"
	boxdialer "github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	sJSON "github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

// The block detector's active side asks through a server what a running outbound cannot show: its
// fallback would go over to another fingerprint and hide what it asks about. So it builds a
// throw-away copy of the outbound in the running instance, nothing registered: no fallback and no
// cache file in the context of the copy, so that it sends what it is told, and records nothing
// under the key of the running one. Its log goes nowhere: a line of an outbound names the address
// of the server, and the log of the instance is shown on the page. Through a detour the outbound
// that runs logs the address as well, in the log of the instance: at debug only (ProbeOutbound.Dial),
// but for xhttp, whose session dials with a context of its own that nothing of the dial reaches.

// the most a probe reads of an answer: the raw bytes of a download are all it asks of it
const probeReadLimit = 1 << 20

// A flow whose last byte came this close to its deadline was still receiving. A limit stalls a
// flow long before it: its bytes come in the first seconds of the 12 or 15 s a request has.
const stillReceiving = 5 * time.Second

// ProbeOptions are what a throw-away copy of an outbound changes.
type ProbeOptions struct {
	// Fingerprint replaces the uTLS fingerprint of an outbound that has uTLS.
	Fingerprint string
	// Detour is the outbound of the instance the copy dials through.
	Detour string
	// Spoof sets tls.spoof on the copy: a forged ClientHello of this whitelisted name goes before
	// the real one, to probe whether it lifts a 16-20KB limit (SuggestMask).
	Spoof string
}

// ProbeOutbound is a throw-away copy of an outbound; Close lets it go.
type ProbeOutbound struct {
	instance *Instance
	scope    *adapter.Scope
	outbound adapter.Outbound
	// detour: it dials through an outbound of the instance
	detour bool
}

// probeContext is the context a copy is built in: the services of the instance, but for the
// fallback, off, and the cache file, none. The registry is a clone: the instance keeps its own.
func (i *Instance) probeContext() context.Context {
	ctx := service.ExtendContext(i.ctx)
	ctx = service.ContextWith[*option.UTLSFallbackOptions](ctx, &option.UTLSFallbackOptions{Enabled: false})
	return service.ContextWith[adapter.CacheFile](ctx, nil)
}

// decodeProbeOutbound reads the JSON of an outbound as a copy of it is to have it. Multiplex goes:
// each dial of a copy is to be a handshake.
func (i *Instance) decodeProbeOutbound(content []byte, options ProbeOptions) (option.Outbound, error) {
	var fields map[string]json.RawMessage
	err := json.Unmarshal(content, &fields)
	if err != nil {
		return option.Outbound{}, err
	}
	delete(fields, "multiplex")
	one, err := json.Marshal(map[string]any{"outbounds": []any{fields}})
	if err != nil {
		return option.Outbound{}, err
	}
	parsed, err := sJSON.UnmarshalExtendedContext[option.Options](i.ctx, one)
	if err != nil {
		return option.Outbound{}, err
	}
	if len(parsed.Outbounds) != 1 {
		return option.Outbound{}, E.New("not one outbound")
	}
	outbound := parsed.Outbounds[0]
	if options.Fingerprint != "" {
		if wrapper, has := outbound.Options.(option.OutboundTLSOptionsWrapper); has {
			if tls := wrapper.TakeOutboundTLSOptions(); tls != nil && tls.UTLS != nil {
				tls.UTLS.Fingerprint = options.Fingerprint
			}
		}
	}
	if options.Spoof != "" {
		if wrapper, has := outbound.Options.(option.OutboundTLSOptionsWrapper); has {
			if tls := wrapper.TakeOutboundTLSOptions(); tls != nil {
				tls.Spoof = options.Spoof
			}
		}
	}
	if options.Detour != "" {
		wrapper, has := outbound.Options.(option.DialerOptionsWrapper)
		if !has {
			return option.Outbound{}, E.New("this outbound does not dial through another")
		}
		dialerOptions := wrapper.TakeDialerOptions()
		dialerOptions.Detour = options.Detour
		wrapper.ReplaceDialerOptions(dialerOptions)
	}
	return outbound, nil
}

// NewProbeOutbound builds a throw-away copy of the outbound of the JSON given, which holds the
// secrets of the server. It comes from a snapshot of the caller: the dialers of the instance are
// the Run goroutine's.
func (i *Instance) NewProbeOutbound(content []byte, options ProbeOptions) (*ProbeOutbound, error) {
	if !i.enter() {
		return nil, ErrClosed
	}
	defer i.leave()
	decoded, err := i.decodeProbeOutbound(content, options)
	if err != nil {
		return nil, err
	}
	registry := service.FromContext[adapter.OutboundRegistry](i.ctx)
	if registry == nil {
		return nil, E.New("this sing-box has no outbounds")
	}
	logFactory := log.NewNOPFactory()
	scope := adapter.NewScope(i.probeContext(), logFactory.Logger())
	outboundCtx := adapter.WithContext(scope.Context(), &adapter.InboundContext{Outbound: decoded.Tag})
	outbound, err := registry.CreateOutbound(outboundCtx, service.FromContext[adapter.Router](i.ctx), logFactory.NewLogger(decoded.Tag), decoded.Tag+"#probe", decoded.Type, decoded.Options)
	if err != nil {
		scope.Close()
		return nil, err
	}
	// what closes a transport or a pool is added at the start of an outbound
	if lifecycle, has := outbound.(adapter.Lifecycle); has {
		for _, stage := range adapter.ListStartStages {
			err = scope.Start("probe outbound", lifecycle, stage)
			if err != nil {
				scope.Close()
				return nil, err
			}
		}
	}
	return &ProbeOutbound{instance: i, scope: scope, outbound: outbound, detour: options.Detour != ""}, nil
}

// Close lets go of what the copy holds.
func (p *ProbeOutbound) Close() error {
	return p.scope.Close()
}

// Dial opens a connection through the copy, the handshake with the server first. Holding the
// instance only while it dials: a Close of the instance cuts the dial first and waits for the
// rest. The connection ends with the context and with the instance.
func (p *ProbeOutbound) Dial(ctx context.Context, address string) (net.Conn, error) {
	i := p.instance
	if !i.enter() {
		return nil, ErrClosed
	}
	defer i.leave()
	if p.detour {
		ctx = log.ContextWithOverrideLevel(ctx, log.LevelDebug)
	}
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(i.ctx, cancel)
	conn, err := p.outbound.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr(address))
	if err != nil {
		stop()
		cancel()
		return nil, err
	}
	return tieConn(ctx, conn, func() {
		stop()
		cancel()
	}), nil
}

// tiedConn is a connection that ends with a context: nothing below it does that for a
// connection after its dial. Closed, it lets go of the context.
type tiedConn struct {
	net.Conn
	release func()
}

func tieConn(ctx context.Context, conn net.Conn, release func()) net.Conn {
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	return &tiedConn{Conn: conn, release: func() {
		stop()
		release()
	}}
}

func (c *tiedConn) Close() error {
	err := c.Conn.Close()
	c.release()
	return err
}

// ProbeTCP connects to the server of the outbound of the JSON given through a dialer of the
// outbound's own options: its mark and its interface keep the connection out of the sing-box of
// the router, and its resolver does not answer from FakeIP.
func (i *Instance) ProbeTCP(ctx context.Context, content []byte) error {
	var head struct {
		Server     string `json:"server"`
		ServerPort uint16 `json:"server_port"`
	}
	err := json.Unmarshal(content, &head)
	if err != nil {
		return err
	}
	if !i.enter() {
		return ErrClosed
	}
	defer i.leave()
	decoded, err := i.decodeProbeOutbound(content, ProbeOptions{})
	if err != nil {
		return err
	}
	wrapper, has := decoded.Options.(option.DialerOptionsWrapper)
	if !has {
		return E.New("this outbound has no dialer of its own")
	}
	destination := M.ParseSocksaddrHostPort(head.Server, head.ServerPort)
	return i.connect(ctx, wrapper.TakeDialerOptions(), destination)
}

// DirectReachable connects to an address past every proxy, with the mark and the interface of
// the direct connections of the configuration.
func (i *Instance) DirectReachable(ctx context.Context, address string) error {
	if !i.enter() {
		return ErrClosed
	}
	defer i.leave()
	return i.connect(ctx, option.DialerOptions{}, M.ParseSocksaddr(address))
}

// connect makes a connection and closes it. The caller has entered the instance.
func (i *Instance) connect(ctx context.Context, options option.DialerOptions, destination M.Socksaddr) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(i.ctx, cancel)
	defer stop()
	outboundDialer, err := boxdialer.New(i.ctx, options, destination.IsDomain())
	if err != nil {
		return err
	}
	conn, err := outboundDialer.DialContext(ctx, N.NetworkTCP, destination)
	if err != nil {
		return err
	}
	return conn.Close()
}

// The words of quic-go's IdleTimeoutError and HandshakeTimeoutError: a QUIC handshake nothing answers
// ends in the first after 5 s. xhttp over h3 passes on the text of an error, not its type
// (transport/v2rayxhttp hideHTTPError). A test holds the text (TestProbeErrorClass).
const (
	quicNoActivity  = "timeout: no recent network activity"
	quicNoHandshake = "timeout: handshake did not complete in time"
)

// ProbeErrorClass tells what an error of a probe met, the only thing of it that may go on: its
// text carries the address of the server. The order counts: a dial that timed out or could not
// resolve a name is a deadline to errors.Is too, and a verification may hold a deadline.
func ProbeErrorClass(err error) detect.ErrorClass {
	if err == nil {
		return detect.ClassNone
	}
	text := err.Error()
	// the words of dns.Router.Lookup, whose causes are errors of connections of their own
	var dnsError *net.DNSError
	if errors.As(err, &dnsError) || strings.Contains(text, "lookup ") {
		return detect.ClassDNS
	}
	var opError *net.OpError
	if errors.As(err, &opError) && opError.Op == "dial" {
		return detect.ClassNoTCP
	}
	var certificateInvalid x509.CertificateInvalidError
	if errors.As(err, &certificateInvalid) {
		return detect.ClassClock
	}
	var unknownAuthority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	// the words of common/tls.realityVerificationFailed; the type is not exported, and a test holds
	// the text (TestProbeErrorClass)
	if errors.As(err, &unknownAuthority) || errors.As(err, &hostname) || strings.Contains(text, "reality verification failed") {
		return detect.ClassVerify
	}
	var timeout net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) || (errors.As(err, &timeout) && timeout.Timeout()) ||
		strings.Contains(text, quicNoActivity) || strings.Contains(text, quicNoHandshake) {
		return detect.ClassNoHello
	}
	// a connection closed under a request: it ends with the instance (tieConn)
	if errors.Is(err, context.Canceled) || errors.Is(err, ErrClosed) || errors.Is(err, net.ErrClosed) {
		return detect.ClassCanceled
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) {
		return detect.ClassCut
	}
	return detect.ClassOther
}

// classAt is the class of an error of an attempt under a context: when the context has ended, the
// error may be of the connection closed for it. A lookup that the deadline ended stays what it
// was: it never got to TCP.
func classAt(ctx context.Context, err error) detect.ErrorClass {
	if ended := ctx.Err(); ended != nil {
		if errors.Is(ended, context.DeadlineExceeded) && ProbeErrorClass(err) == detect.ClassDNS {
			return detect.ClassDNS
		}
		return ProbeErrorClass(ended)
	}
	return ProbeErrorClass(err)
}

// exchange asks for the address over a connection and counts the raw bytes of the answer. It
// reads no further than the answer, or the first end of it.
func exchange(ctx context.Context, conn net.Conn, address string) detect.Attempt {
	attempt := detect.Attempt{Handshake: true}
	if deadline, has := ctx.Deadline(); has {
		_ = conn.SetDeadline(deadline)
	}
	request, err := http.NewRequest(http.MethodGet, address, nil)
	if err != nil {
		attempt.Class = detect.ClassOther
		return attempt
	}
	request.Close = true
	err = request.Write(conn)
	if err != nil {
		attempt.Class = classAt(ctx, err)
		return attempt
	}
	counted := &countingReader{reader: conn}
	response, err := http.ReadResponse(bufio.NewReader(counted), request)
	if err != nil {
		attempt.Bytes, attempt.Class = counted.count, classAt(ctx, err)
		return attempt
	}
	defer response.Body.Close()
	attempt.Status = response.StatusCode
	_, err = io.Copy(io.Discard, io.LimitReader(response.Body, probeReadLimit))
	attempt.Bytes = counted.count
	if err != nil {
		attempt.Class = classAt(ctx, err)
		attempt.Receiving = attempt.Class == detect.ClassNoHello && counted.count > 0 && time.Since(counted.last) < stillReceiving
	}
	return attempt
}

type countingReader struct {
	reader io.Reader
	count  int64
	// last is when the last byte came
	last time.Time
}

func (r *countingReader) Read(buffer []byte) (int, error) {
	n, err := r.reader.Read(buffer)
	r.count += int64(n)
	if n > 0 {
		r.last = time.Now()
	}
	return n, err
}

// targetAddress is the host and the port of an address of a probe.
func targetAddress(address string) (string, error) {
	parsed, err := url.Parse(address)
	if err != nil {
		return "", err
	}
	if parsed.Port() != "" {
		return parsed.Host, nil
	}
	return net.JoinHostPort(parsed.Hostname(), "80"), nil
}

// how many masks SuggestMask tries at once, and how long one probe may take.
const (
	probeMaskParallel = 6
	probeMaskPer      = 12 * time.Second
)

// SuggestMask looks for a whitelisted SNI that lifts a 16-20KB limit on the server of content: each
// candidate is a throw-away copy with tls.spoof set to it that pulls the 64KB probe target, and the
// first that carries it in full (the limit lifted) wins. Up to probeMaskParallel run at once, each
// within probeMaskPer, the whole within ctx (the caller sets the budget). The candidates come from
// names in their order until it is closed, so the caller can add names it gets while the first
// are probed; nil means WhiteSNICandidates. It returns the winning name and how many were tried;
// "" with no error when none worked, an error only on a setup failure. tls.spoof needs the
// engine's own socket (CAP_NET_ADMIN), so this must run in the running instance, not a sandbox.
func (i *Instance) SuggestMask(ctx context.Context, content []byte, names <-chan string) (string, int, error) {
	if names == nil {
		names = NamesOf(WhiteSNICandidates)
	}
	target, err := targetAddress(detect.ProbeTarget)
	if err != nil {
		return "", 0, err
	}
	full := detect.DefaultPolicy.Target * detect.DefaultPolicy.FullPercent / 100
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		sni string
		ok  bool
	}
	jobs := make(chan string)
	results := make(chan result)
	var wg sync.WaitGroup
	for worker := 0; worker < probeMaskParallel; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for cand := range jobs {
				ok := i.maskLifts(ctx, content, cand, target, full)
				select {
				case results <- result{cand, ok}:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for {
			var cand string
			var open bool
			select {
			case cand, open = <-names:
				if !open {
					return
				}
			case <-ctx.Done():
				return
			}
			select {
			case jobs <- cand:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		wg.Wait()
		close(results)
	}()
	scanned := 0
	for r := range results {
		scanned++
		if r.ok {
			cancel() // the rest stop; the workers drain their sends against ctx.Done
			return r.sni, scanned, nil
		}
	}
	return "", scanned, nil
}

// maskLifts tells whether a tls.spoof of name carries the probe target in full, i.e. the limit is
// lifted. A short or stalled pull (a flow still cut) is not full.
func (i *Instance) maskLifts(ctx context.Context, content []byte, name, target string, full int64) bool {
	probeCtx, cancel := context.WithTimeout(ctx, probeMaskPer)
	defer cancel()
	outbound, err := i.NewProbeOutbound(content, ProbeOptions{Spoof: name})
	if err != nil {
		return false
	}
	defer outbound.Close()
	conn, err := outbound.Dial(probeCtx, target)
	if err != nil {
		return false
	}
	defer conn.Close()
	attempt := exchange(probeCtx, conn, detect.ProbeTarget)
	return attempt.Bytes >= full && !attempt.Receiving
}

// Prober is the instance as the runner of the block detector uses it (detect.Run).
func (i *Instance) Prober() detect.Prober {
	return instanceProber{i}
}

type instanceProber struct {
	instance *Instance
}

func (p instanceProber) TCP(ctx context.Context, server detect.Server) detect.ErrorClass {
	err := p.instance.ProbeTCP(ctx, server.Content)
	if err == nil {
		return detect.ClassNone
	}
	class := classAt(ctx, err)
	if class == detect.ClassDNS || class == detect.ClassCanceled {
		return class
	}
	return detect.ClassNoTCP
}

func (p instanceProber) Fetch(ctx context.Context, server detect.Server, request detect.ProbeRequest) detect.Attempt {
	target := request.URL
	if target == "" {
		// a lazy protocol sends nothing of it: a dial of an address has to name one
		target = detect.ProbeTarget
	}
	address, err := targetAddress(target)
	if err != nil {
		return detect.Attempt{Class: detect.ClassOther}
	}
	outbound, err := p.instance.NewProbeOutbound(server.Content, ProbeOptions{Fingerprint: request.Fingerprint, Detour: request.Detour})
	if err != nil {
		return detect.Attempt{Class: classAt(ctx, err)}
	}
	defer outbound.Close()
	conn, err := outbound.Dial(ctx, address)
	if err != nil {
		return detect.Attempt{Class: classAt(ctx, err)}
	}
	defer conn.Close()
	if request.URL == "" {
		return detect.Attempt{Handshake: true}
	}
	return exchange(ctx, conn, request.URL)
}

func (p instanceProber) Control(ctx context.Context, tag string, target string) detect.Attempt {
	i := p.instance
	address, err := targetAddress(target)
	if err != nil {
		return detect.Attempt{Class: detect.ClassOther}
	}
	conn, err := i.Dial(ctx, tag, address)
	if err != nil {
		return detect.Attempt{Class: classAt(ctx, err)}
	}
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(i.ctx, cancel)
	tied := tieConn(ctx, conn, func() {
		stop()
		cancel()
	})
	defer tied.Close()
	return exchange(ctx, tied, target)
}

func (p instanceProber) Reachable(ctx context.Context, address string) bool {
	return p.instance.DirectReachable(ctx, address) == nil
}
