//go:build tinfoil_conformance

package conformance

import (
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/tinfoilsh/tinfoil-go/verifier/client"
)

// RejectionCode maps a verification error to the wire rejection code.
//
// This function works by trying to match against error strings. As the code
// stands today, only the reference-values step is tagged with a "reference
// values:" substring. The document and cpu-evidence layers add no marker of
// their own, so anything else is attributed to the envelope.
//
// The match is anchored at the start of each error in the unwrap chain rather
// than run across the whole message. Document fields are quoted into error
// text, so a document that names its own format "reference values:" would
// otherwise have an envelope failure reported as a provenance one.
func RejectionCode(err error) string {
	for e := err; e != nil; e = errors.Unwrap(e) {
		if strings.HasPrefix(e.Error(), "reference values:") {
			return "PROVENANCE_REJECTED"
		}
	}
	return "ENVELOPE_REJECTED"
}

// TLSSPKIFingerprint dials host:443 and returns the SDK's canonical SPKI
// fingerprint of the presented leaf (client.ConnectionCertFP — the same
// computation TLSBoundRoundTripper enforces). Certificate-chain verification
// is skipped on purpose: trust comes from matching the attested fingerprint,
// not the public PKI.
func TLSSPKIFingerprint(host string) (string, error) {
	addr, serverName := host, host
	if h, _, err := net.SplitHostPort(host); err == nil {
		serverName = h // host already carries a port
	} else {
		addr = net.JoinHostPort(host, "443")
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr,
		&tls.Config{ServerName: serverName, InsecureSkipVerify: true}) //nolint:gosec // bound by SPKI, not PKI
	if err != nil {
		return "", err
	}
	defer conn.Close()
	return client.ConnectionCertFP(conn.ConnectionState())
}
