package clock

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/podkop-net/podkop-experimental/src/backend/dataplane"
	E "github.com/sagernet/sing/common/exceptions"
)

// HTTPSTime is the time an HTTPS server tells in the Date header of its answer, the server
// at address (host:port, connected directly, never through the proxy) under the name host.
// Its certificate is verified at that time, not at the clock of the router: the clock may be
// wrong by months, and only a server with a valid certificate of host can tell a time that
// is taken. A
// request of the DoH path is answered by any DoH server, with an error or not; the status
// does not matter. The Date has whole seconds: half a second is added.
func HTTPSTime(ctx context.Context, address string, host string, path string, roots *x509.CertPool) (time.Time, error) {
	dialer := net.Dialer{Control: dataplane.MarkedControl}
	raw, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return time.Time{}, err
	}
	defer raw.Close()
	if deadline, set := ctx.Deadline(); set {
		_ = raw.SetDeadline(deadline)
	}
	serverName := host
	if _, err := netip.ParseAddr(host); err == nil {
		// no SNI for an address; the certificate is checked for it below
		serverName = ""
	}
	// verified below, at the time the server tells
	conn := tls.Client(raw, &tls.Config{ServerName: serverName, InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
	err = conn.HandshakeContext(ctx)
	if err != nil {
		return time.Time{}, E.Cause(err, "TLS handshake")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodHead, "https://"+host+path, nil)
	if err != nil {
		return time.Time{}, err
	}
	request.Header.Set("Accept", "application/dns-message")
	request.Close = true
	err = request.Write(conn)
	if err != nil {
		return time.Time{}, E.Cause(err, "send the request")
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), request)
	if err != nil {
		return time.Time{}, E.Cause(err, "read the answer")
	}
	response.Body.Close()
	told, err := http.ParseTime(response.Header.Get("Date"))
	if err != nil {
		return time.Time{}, E.New("the answer has no Date")
	}
	told = told.Add(500 * time.Millisecond)
	certificates := conn.ConnectionState().PeerCertificates
	if len(certificates) == 0 {
		return time.Time{}, E.New("no certificate")
	}
	intermediates := x509.NewCertPool()
	for _, certificate := range certificates[1:] {
		intermediates.AddCert(certificate)
	}
	_, err = certificates[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: told, DNSName: host})
	if err != nil {
		return time.Time{}, E.Cause(err, "the certificate at the time the server tells, ", told.UTC().Format(time.RFC3339))
	}
	return told, nil
}
