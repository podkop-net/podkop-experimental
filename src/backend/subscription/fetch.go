package subscription

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Route is a way to the provider.
type Route struct {
	// Name is "direct", or the name of the outbound the request goes through.
	Name string
	// Direct tells that no proxy is on the way: only such a route takes an address of plain
	// HTTP, whose token a proxy would read.
	Direct bool
	Dial   func(ctx context.Context, network string, address string) (net.Conn, error)
}

// Answer is a list as the provider sent it.
type Answer struct {
	Body   []byte
	Header http.Header
	// Route is the name of the route it came by.
	Route string
}

// MaxBody is the most a list may have: thousands of links.
const MaxBody = 4 << 20

// infoHeaders are what a provider tells about the subscription, kept with the list.
var infoHeaders = []string{"subscription-userinfo", "profile-update-interval", "profile-title", "announce", "support-url", "profile-web-page-url", "subscription-refill-date"}

// Info returns what an answer tells about the subscription: its headers, or the lines some
// providers put at the top of the list in their place (bodyInfo).
func (a *Answer) Info() map[string]string {
	info := bodyInfo(a.Body)
	if info == nil {
		info = make(map[string]string)
	}
	for _, name := range infoHeaders {
		if value := a.Header.Get(name); value != "" {
			info[name] = value
		}
	}
	return info
}

// roots are the certificates the server of a provider is checked against: those of the
// system, but in a test.
var roots *x509.CertPool

// Failure is why a download, or one try of it, came to nothing: a code the page translates,
// its arguments, and the English text of the log and the command line. A failure names
// neither the address nor the host of the provider.
type Failure struct {
	Code string
	Args []string
	Text string
	// final tells an answer of the provider itself: another way would get the same
	final bool
}

func (f *Failure) Error() string {
	return f.Text
}

func fail(code string, final bool, text string, args ...string) *Failure {
	return &Failure{Code: code, Args: args, Text: text, final: final}
}

// Plan is how the ways to the provider are started. The first way starts at once; the next
// one starts beside those under way when a try fails, when no try showed progress for Wait
// (none has the headers yet) or Body (one gets the body), and when the youngest try is Total
// old. A try under way is not stopped for it: the first to bring the list wins. The waits
// come from the downloads of the subscription before (the supervisor keeps them): a slow
// provider is waited for, and a broken way is left soon.
type Plan struct {
	Wait  time.Duration
	Body  time.Duration
	Total time.Duration
	// Together starts the first way after the direct one beside it: the direct way brought
	// no list the last time
	Together bool
}

// DefaultPlan is the plan of a subscription with no downloads before: 5 s is what a way had
// before the plan, 3 s in the body a choice (a body that stopped on the way does not start
// again), 10 s what a way had in the background.
var DefaultPlan = Plan{Wait: 5 * time.Second, Body: 3 * time.Second, Total: 10 * time.Second}

// The hard limits of a try, past which its way failed: the connection (sing-box's own limit
// of direct-out), the TLS handshake (sing-box's TCP timeout), and a time with no progress
// (that of the rule sets of the engine). A try has no limit of its own beyond these; the
// whole download has the budget of its context.
const (
	connectLimit = 5 * time.Second
	tlsLimit     = 15 * time.Second
	stallLimit   = 30 * time.Second
	// at most this many ways are tried at once: bursts of TLS hellos to one name are what
	// the DPI of some ISPs penalises
	mostTries  = 3
	watchEvery = 100 * time.Millisecond
)

// The phases of a try.
const (
	PhaseConnect  = "connect"
	PhaseTLS      = "tls"
	PhaseWait     = "wait"
	PhaseBody     = "body"
	PhaseDone     = "done"
	PhaseFailed   = "failed"
	PhaseCanceled = "canceled"
)

// Try is a try of a download by one way, as the page shows it.
type Try struct {
	Route   string
	Phase   string
	Started time.Time
	Took    time.Duration
	// FirstByte is the time from the start to the first byte of the answer; Pause the longest
	// time with no byte of the body.
	FirstByte time.Duration
	Pause     time.Duration
	Bytes     int64
	// Failure is why it failed; none when it brought the list or is under way.
	Failure *Failure
}

var (
	errConnect    = errors.New("no connection in time")
	errStall      = errors.New("no progress in time")
	errSuperseded = errors.New("another way brought the list")
)

// Download asks the provider at the address, with the headers, by the routes as the plan
// starts them (Plan), and returns the first list that comes. A route that does not reach the
// provider, or gets a web page (the page of an ISP for a blocked site, as a rule), is
// followed by the next one; an answer of the provider itself (a code of no account, the
// marks of a refused device) ends the download; a status that may come from a CDN or a
// firewall on the way (403, 429, 5xx) is tried by one more way. ctx bounds the download.
// report, when given, is called with the tries as they go.
func Download(ctx context.Context, address string, header http.Header, routes []Route, plan Plan, report func([]Try)) (*Answer, []Try, error) {
	target, err := url.Parse(address)
	if err != nil || (target.Scheme != "https" && target.Scheme != "http") || target.Host == "" {
		return nil, nil, fail("address", true, "the address of the subscription is not an address of HTTP or HTTPS")
	}
	var ways []Route
	for _, route := range routes {
		if target.Scheme == "http" && !route.Direct {
			// the token would go through a proxy as it is
			continue
		}
		ways = append(ways, route)
	}
	if len(ways) == 0 {
		return nil, nil, fail("noway", true, "there was no way to the provider to try")
	}
	d := &download{target: target, header: header, ways: ways, plan: plan, done: make(chan *try, len(ways))}
	return d.run(ctx, report)
}

// download is the state of one Download.
type download struct {
	target  *url.URL
	header  http.Header
	ways    []Route
	plan    Plan
	tries   []*try
	next    int
	running int
	done    chan *try
}

func (d *download) run(ctx context.Context, report func([]Try)) (*Answer, []Try, error) {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(errSuperseded)
	d.start(ctx)
	if d.plan.Together && d.ways[0].Direct {
		d.start(ctx)
	}
	watch := time.NewTicker(watchEvery)
	defer watch.Stop()
	var status *Failure
	statuses := 0
	for {
		select {
		case finished := <-d.done:
			d.running--
			if finished.answer != nil {
				cancel(errSuperseded)
				return finished.answer, d.ended(report, canceledTry), nil
			}
			failure := finished.result()
			if failure.final {
				cancel(errSuperseded)
				return nil, d.ended(report, canceledTry), failure
			}
			if failure.Code == "status" {
				// a status of the provider: one more way, then it is the answer
				statuses++
				status = providerStatus(failure)
				if statuses >= 2 {
					cancel(errSuperseded)
					return nil, d.ended(report, canceledTry), status
				}
			}
			if d.next < len(d.ways) {
				d.start(ctx)
			} else if d.running == 0 {
				tries := d.snapshot(report)
				if status != nil {
					return nil, tries, status
				}
				return nil, tries, unreachable(tries)
			}
			d.snapshot(report)
		case <-watch.C:
			d.watch(ctx)
			d.snapshot(report)
		case <-ctx.Done():
			// the budget of the download, or its caller gave up
			for _, item := range d.tries {
				item.stop(context.Cause(ctx))
			}
			tries := d.ended(report, timedOut)
			if status != nil {
				return nil, tries, status
			}
			return nil, tries, unreachable(tries)
		}
	}
}

// start starts the next way.
func (d *download) start(ctx context.Context) {
	if d.next >= len(d.ways) {
		return
	}
	route := d.ways[d.next]
	d.next++
	ctx, cancel := context.WithCancelCause(ctx)
	now := time.Now()
	item := &try{route: route, started: now, last: now, phase: PhaseConnect, cancel: cancel}
	d.tries = append(d.tries, item)
	d.running++
	go func() {
		item.run(ctx, d.target, d.header)
		d.done <- item
	}()
}

// watch stops the tries past their hard limits and starts the next way as the plan says.
func (d *download) watch(ctx context.Context) {
	now := time.Now()
	idle, youngest := time.Duration(-1), time.Duration(-1)
	body := false
	for _, item := range d.tries {
		item.access.Lock()
		running, last, started, phase := item.finished == 0, item.last, item.started, item.phase
		item.access.Unlock()
		if !running {
			continue
		}
		if now.Sub(last) > stallLimit {
			item.stop(errStall)
			continue
		}
		if idle < 0 || now.Sub(last) < idle {
			idle = now.Sub(last)
		}
		if youngest < 0 || now.Sub(started) < youngest {
			youngest = now.Sub(started)
		}
		body = body || phase == PhaseBody
	}
	if idle < 0 || d.running >= mostTries || d.next >= len(d.ways) {
		return
	}
	wait := d.plan.Wait
	if body {
		wait = d.plan.Body
	}
	if idle >= wait || youngest >= d.plan.Total {
		d.start(ctx)
	}
}

// ended is the tries when the download ends: those still under way are told as they end
// now (stopping is theirs to finish in their goroutines), and report is told them.
func (d *download) ended(report func([]Try), as func(took time.Duration) *Failure) []Try {
	tries := d.snapshot(nil)
	for index := range tries {
		switch tries[index].Phase {
		case PhaseDone, PhaseFailed, PhaseCanceled:
			continue
		}
		tries[index].Failure = as(tries[index].Took)
		tries[index].Phase = PhaseFailed
		if tries[index].Failure.Code == "canceled" {
			tries[index].Phase = PhaseCanceled
		}
	}
	if report != nil {
		report(tries)
	}
	return tries
}

func canceledTry(time.Duration) *Failure {
	return fail("canceled", false, "another way brought the list first")
}

// snapshot is the tries as they are; report is told them.
func (d *download) snapshot(report func([]Try)) []Try {
	tries := make([]Try, 0, len(d.tries))
	for _, item := range d.tries {
		tries = append(tries, item.view())
	}
	if report != nil {
		report(tries)
	}
	return tries
}

// unreachable is the failure of a download no way of which brought the list.
func unreachable(tries []Try) *Failure {
	var reasons []string
	pages := 0
	for _, item := range tries {
		if item.Failure == nil {
			continue
		}
		if item.Failure.Code == "page" {
			pages++
		}
		reasons = append(reasons, item.Route+": "+item.Failure.Text)
	}
	if pages > 0 && pages == len(tries) {
		return fail("page", true, "every way got a web page instead of the list: it may be the address of the provider's site, not of the subscription, or a page of the ISP")
	}
	return fail("unreachable", false, "the provider could not be reached ("+strings.Join(reasons, "; ")+")")
}

// providerStatus is the failure of a download whose provider answered a status that is no
// list.
func providerStatus(failure *Failure) *Failure {
	code := failure.Args[0]
	switch number, _ := strconv.Atoi(code); {
	case number == http.StatusTooManyRequests:
		return fail("wait", true, "the provider asks to wait (HTTP 429): the router tries again later", code)
	case number >= 500:
		return fail("server", true, "the provider's server failed (HTTP "+code+"): the router tries again later", code)
	default:
		return fail("refused", true, "the provider refused the address (HTTP "+code+"): it is wrong or out of date, or the subscription is blocked", code)
	}
}

func timedOut(took time.Duration) *Failure {
	seconds := strconv.Itoa(int((took + time.Second/2) / time.Second))
	return fail("timeout", false, "no answer in "+seconds+" s", seconds)
}

// try is one way of a download, under way or done.
type try struct {
	route   Route
	started time.Time
	cancel  context.CancelCauseFunc

	access    sync.Mutex
	phase     string
	last      time.Time
	firstByte time.Duration
	pause     time.Duration
	bytes     int64
	finished  time.Duration
	answer    *Answer
	failure   *Failure
}

func (t *try) stop(cause error) {
	t.cancel(cause)
}

func (t *try) moved(phase string) {
	t.access.Lock()
	defer t.access.Unlock()
	t.phase, t.last = phase, time.Now()
}

func (t *try) received(count int) {
	t.access.Lock()
	defer t.access.Unlock()
	now := time.Now()
	if gap := now.Sub(t.last); t.phase == PhaseBody && gap > t.pause {
		t.pause = gap
	}
	t.bytes += int64(count)
	t.last = now
}

func (t *try) result() *Failure {
	t.access.Lock()
	defer t.access.Unlock()
	return t.failure
}

func (t *try) view() Try {
	t.access.Lock()
	defer t.access.Unlock()
	took := t.finished
	if took == 0 {
		took = time.Since(t.started)
	}
	return Try{Route: t.route.Name, Phase: t.phase, Started: t.started, Took: took, FirstByte: t.firstByte, Pause: t.pause, Bytes: t.bytes, Failure: t.failure}
}

// end records what the try came to.
func (t *try) end(answer *Answer, failure *Failure) {
	t.access.Lock()
	defer t.access.Unlock()
	t.finished = time.Since(t.started)
	t.answer, t.failure = answer, failure
	switch {
	case answer != nil:
		t.phase = PhaseDone
	case failure.Code == "canceled":
		t.phase = PhaseCanceled
	default:
		t.phase = PhaseFailed
	}
}

func (t *try) run(ctx context.Context, target *url.URL, header http.Header) {
	answer, failure := t.ask(ctx, target, header)
	if failure != nil && ctx.Err() != nil {
		failure = t.stopped(ctx, failure)
	}
	t.end(answer, failure)
}

func (t *try) ask(ctx context.Context, target *url.URL, header http.Header) (*Answer, *Failure) {
	var dialed sync.Once
	dial := func(dialContext context.Context, network string, address string) (net.Conn, error) {
		limit := time.AfterFunc(connectLimit, func() { t.stop(errConnect) })
		conn, err := t.route.Dial(dialContext, network, address)
		limit.Stop()
		if err == nil {
			dialed.Do(func() {
				if target.Scheme == "https" {
					t.moved(PhaseTLS)
				} else {
					t.moved(PhaseWait)
				}
			})
		}
		return conn, err
	}
	transport := &http.Transport{
		DialContext:         dial,
		TLSClientConfig:     &tls.Config{RootCAs: roots},
		ForceAttemptHTTP2:   true,
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: tlsLimit,
	}
	defer transport.CloseIdleConnections()
	trace := &httptrace.ClientTrace{
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			if err == nil {
				t.moved(PhaseWait)
			}
		},
		GotFirstResponseByte: func() {
			t.access.Lock()
			t.firstByte, t.last = time.Since(t.started), time.Now()
			t.access.Unlock()
		},
	}
	request, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, fail("address", true, "the address of the subscription cannot be asked")
	}
	request.Header = header.Clone()
	response, err := (&http.Client{Transport: transport}).Do(request)
	if err != nil {
		return nil, t.reason(err, target)
	}
	defer response.Body.Close()
	if failure := answered(response); failure != nil {
		return nil, failure
	}
	t.moved(PhaseBody)
	var body bytes.Buffer
	chunk := make([]byte, 32<<10)
	for {
		count, err := response.Body.Read(chunk)
		if count > 0 {
			body.Write(chunk[:count])
			t.received(count)
			if body.Len() > MaxBody {
				return nil, fail("toobig", true, "the list is larger than "+strconv.Itoa(MaxBody>>20)+" MiB", strconv.Itoa(MaxBody>>20))
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			if ctx.Err() != nil {
				return nil, fail("cut", false, "the list broke off")
			}
			return nil, fail("cut", false, "the list broke off: "+plain(err, target))
		}
	}
	if response.StatusCode == http.StatusOK && isPage(response.Header, body.Bytes()) {
		return nil, fail("page", false, "a web page instead of the list")
	}
	return &Answer{Body: body.Bytes(), Header: response.Header, Route: t.route.Name}, nil
}

// answered is what the headers of an answer tell before its body: the marks of a device
// the provider refused, or a status that is no list.
func answered(response *http.Response) *Failure {
	if failure := refusedDevice(response.Header); failure != nil {
		return failure
	}
	code := strconv.Itoa(response.StatusCode)
	switch status := response.StatusCode; {
	case status == http.StatusOK:
		return nil
	case status == http.StatusNoContent:
		return fail("nocontent", true, "the provider sent nothing (HTTP 204): the address is wrong, or the subscription was removed")
	case status == http.StatusUnauthorized || status == http.StatusProxyAuthRequired:
		return fail("refused", true, "the provider refused the address (HTTP "+code+"): it is wrong or out of date, or the subscription is blocked", code)
	case status == http.StatusNotFound || status == http.StatusGone:
		return fail("notfound", true, "the provider has no subscription at this address (HTTP "+code+"): the address is wrong, or the subscription was removed", code)
	case status == http.StatusUnavailableForLegalReasons:
		return fail("blocked", false, "blocked on the way (HTTP 451)")
	case status == http.StatusForbidden || status == http.StatusTooManyRequests || status >= 500:
		// may come from a CDN or a firewall that judges the address of the client
		return fail("status", false, "HTTP "+code, code)
	default:
		return fail("http", true, "the provider answered HTTP "+code+" instead of the list", code)
	}
}

// stopped is why a try stopped by its context failed: its hard limits, another way that
// brought the list, or the end of the download.
func (t *try) stopped(ctx context.Context, failure *Failure) *Failure {
	t.access.Lock()
	phase, bytes, took := t.phase, t.bytes, time.Since(t.started)
	t.access.Unlock()
	switch cause := context.Cause(ctx); {
	case errors.Is(cause, errSuperseded):
		return fail("canceled", false, "another way brought the list first")
	case errors.Is(cause, errConnect):
		return fail("timeout", false, "no connection in "+strconv.Itoa(int(connectLimit/time.Second))+" s", strconv.Itoa(int(connectLimit/time.Second)))
	case errors.Is(cause, errStall) && phase == PhaseBody:
		kib := strconv.FormatInt((bytes+512)/1024, 10)
		return fail("stalled", false, "the transfer stopped at "+kib+" KB", kib)
	case errors.Is(cause, errStall), errors.Is(cause, context.DeadlineExceeded):
		return timedOut(took)
	}
	return failure
}

// reason is why a request of a try failed, by the error of the request.
func (t *try) reason(err error, target *url.URL) *Failure {
	t.access.Lock()
	phase := t.phase
	t.access.Unlock()
	message := plain(err, target)
	var dnsError *net.DNSError
	var certificate x509.CertificateInvalidError
	var authority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var record tls.RecordHeaderError
	switch {
	case errors.As(err, &dnsError):
		return fail("dns", false, "the name of the provider is not found")
	case errors.Is(err, syscall.ECONNREFUSED):
		return fail("refused-connection", false, "the connection is refused")
	case errors.As(err, &certificate) && (certificate.Reason == x509.Expired):
		return fail("cert", false, "the certificate is not valid by the router's clock: check the clock")
	case strings.Contains(message, "TLS handshake timeout"):
		seconds := strconv.Itoa(int(tlsLimit / time.Second))
		return fail("timeout", false, "no secure connection in "+seconds+" s", seconds)
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPIPE),
		phase == PhaseTLS && (errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)):
		return fail("reset", false, "the connection is reset")
	case errors.As(err, &authority), errors.As(err, &hostname), errors.As(err, &record), strings.Contains(message, "tls: "):
		return fail("tls", false, "the secure connection failed")
	}
	return fail("other", false, message)
}

// isPage tells a web page by its type or its first byte.
func isPage(header http.Header, body []byte) bool {
	if mediaType, _, err := mime.ParseMediaType(header.Get("Content-Type")); err == nil && mediaType == "text/html" {
		return true
	}
	text := strings.TrimSpace(strings.TrimPrefix(string(body[:min(len(body), 512)]), "\ufeff"))
	return strings.HasPrefix(text, "<")
}

// refusedDevice is why a provider of Remnawave did not take the device: its headers mark
// an answer whose list is a placeholder, with the text of the provider (announce).
func refusedDevice(header http.Header) *Failure {
	isSet := func(name string) bool { return strings.EqualFold(header.Get(name), "true") }
	announce := decodedText(header.Get("announce"))
	said := ""
	if announce != "" {
		said = ": " + announce
	}
	switch {
	case isSet("x-hwid-max-devices-reached"):
		return fail("devices", true, "the provider's limit of devices is reached: delete an old device in the provider's bot or account, then check again"+said, announce)
	case isSet("x-hwid-not-supported"), isSet("x-hwid-limit"):
		return fail("hwid", true, "the provider did not take the identifier of this device (HWID)"+said, announce)
	}
	return nil
}

// decodedText is a header value a provider may write in base64 with the prefix "base64:".
func decodedText(value string) string {
	if rest, found := strings.CutPrefix(value, "base64:"); found {
		if decoded, err := base64.StdEncoding.DecodeString(rest); err == nil {
			value = string(decoded)
		}
	}
	return strings.Join(strings.Fields(value), " ")
}

// plain is the message of a failed request without the address and the host.
func plain(err error, target *url.URL) string {
	var urlError *url.Error
	if errors.As(err, &urlError) {
		err = urlError.Err
	}
	message := err.Error()
	if errors.Is(err, context.DeadlineExceeded) {
		message = "no answer in time"
	}
	message = strings.ReplaceAll(message, target.String(), "the address")
	if host := target.Hostname(); host != "" {
		message = strings.ReplaceAll(message, host, "the provider")
	}
	return message
}
