package subscription

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

// Route is a way to the provider.
type Route struct {
	// Name is "direct", or the tag of the outbound the request goes through.
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
var infoHeaders = []string{"subscription-userinfo", "profile-update-interval", "profile-title", "announce", "support-url", "profile-web-page-url"}

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

// errFinal is an answer of the provider itself: another route would get the same.
type errFinal struct{ error }

// Download asks the provider at the address, with the headers, by each route in turn until
// one brings a list. A route that does not reach the provider, or gets a web page (the page
// of an ISP for a blocked site, as a rule), is followed by the next one; an answer of the
// provider that is no list ends the tries. A try takes each at most; ctx bounds them all.
// The messages name neither the address nor the host.
func Download(ctx context.Context, address string, header http.Header, routes []Route, each time.Duration) (*Answer, error) {
	target, err := url.Parse(address)
	if err != nil || (target.Scheme != "https" && target.Scheme != "http") || target.Host == "" {
		return nil, E.New("the address of the subscription is not an address of HTTP or HTTPS")
	}
	var failures []string
	for _, route := range routes {
		if target.Scheme == "http" && !route.Direct {
			// the token would go through a proxy as it is
			continue
		}
		if ctx.Err() != nil {
			break
		}
		answer, err := try(ctx, target, header, route, each)
		if err == nil {
			return answer, nil
		}
		var final errFinal
		if errors.As(err, &final) {
			return nil, final.error
		}
		failures = append(failures, route.Name+": "+err.Error())
	}
	if len(failures) == 0 {
		return nil, E.New("there was no way to the provider to try")
	}
	return nil, E.New("the provider could not be reached (", strings.Join(failures, "; "), ")")
}

func try(ctx context.Context, target *url.URL, header http.Header, route Route, each time.Duration) (*Answer, error) {
	ctx, cancel := context.WithTimeout(ctx, each)
	defer cancel()
	transport := &http.Transport{
		DialContext:         route.Dial,
		TLSClientConfig:     &tls.Config{RootCAs: roots},
		ForceAttemptHTTP2:   true,
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: each,
	}
	defer transport.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, errFinal{E.New("the address of the subscription cannot be asked")}
	}
	request.Header = header.Clone()
	response, err := (&http.Client{Transport: transport}).Do(request)
	if err != nil {
		return nil, E.New(plain(err, target))
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, MaxBody+1))
	if err != nil {
		return nil, E.New("the list was cut off: ", plain(err, target))
	}
	if len(body) > MaxBody {
		return nil, errFinal{E.New("the list is larger than ", MaxBody>>20, " MiB")}
	}
	if reason := refusedDevice(response.Header); reason != "" {
		return nil, errFinal{E.New(reason)}
	}
	switch {
	case response.StatusCode == http.StatusOK && isPage(response.Header, body):
		return nil, ErrPage
	case response.StatusCode == http.StatusOK:
		return &Answer{Body: body, Header: response.Header, Route: route.Name}, nil
	case response.StatusCode == http.StatusNoContent:
		return nil, errFinal{E.New("the provider sent nothing: the address may be of no account")}
	case response.StatusCode == http.StatusUnavailableForLegalReasons:
		return nil, E.New("blocked on the way (", response.Status, ")")
	default:
		return nil, errFinal{E.New("the provider answers ", response.Status)}
	}
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
func refusedDevice(header http.Header) string {
	isSet := func(name string) bool { return strings.EqualFold(header.Get(name), "true") }
	var reason string
	switch {
	case isSet("x-hwid-max-devices-reached"):
		reason = "the provider's limit of devices is reached: free a place in the devices of the subscription"
	case isSet("x-hwid-not-supported"), isSet("x-hwid-limit"):
		reason = "the provider did not take the identifier of this device (HWID)"
	default:
		return ""
	}
	if announce := decodedText(header.Get("announce")); announce != "" {
		reason += ": " + announce
	}
	return reason
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
