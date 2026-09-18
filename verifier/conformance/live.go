//go:build tinfoil_conformance

package conformance

import (
	"crypto/tls"
	"net"
	"strings"
	"time"

	"github.com/tinfoilsh/tinfoil-go/verifier/client"
)

// RejectionCode maps a client.VerifyDocumentV3 error to the wire rejection
// code by our own stable wrapping prefixes (verifier/client/verify.go) — not
// by matching foreign error text. Policy failures surface under the cpu
// evidence step in the public API, so they attribute as QUOTE_REJECTED.
func RejectionCode(err error) string {
	s := err.Error()
	switch {
	case strings.HasPrefix(s, "envelope:"):
		return "ENVELOPE_REJECTED"
	case strings.HasPrefix(s, "reference values:"):
		return "PROVENANCE_REJECTED"
	case strings.HasPrefix(s, "cpu evidence:"):
		return "QUOTE_REJECTED"
	}
	return "ENVELOPE_REJECTED" // unreachable for the current wrapping
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
