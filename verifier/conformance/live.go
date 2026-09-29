//go:build tinfoil_conformance

package conformance

import (
	"crypto/tls"
	"net"
	"time"

	"github.com/tinfoilsh/tinfoil-go/verifier/client"
)

// RejectionCode maps the layer Verifier.VerifyV3WithLayer reports to the wire
// rejection code. A rejection with no layer, which only an unusable Verifier
// produces, is attributed to the envelope.
func RejectionCode(layer string) string {
	switch layer {
	case "provenance":
		return "PROVENANCE_REJECTED"
	case "quote":
		return "QUOTE_REJECTED"
	case "policy":
		return "POLICY_REJECTED"
	default:
		return "ENVELOPE_REJECTED"
	}
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
