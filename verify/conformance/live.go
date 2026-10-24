//go:build tinfoil_conformance

package conformance

import (
	"crypto/tls"
	"errors"
	"net"
	"time"

	"github.com/tinfoilsh/tinfoil-go/verify"
)

// RejectionCode reports a VerifyV3 error the way the wire contract does: a
// VerificationError is rejected with its layer's code, and a UsageError means
// the input was malformed. Anything else, including a VerificationError
// without a known layer, is a bug in the verifier and reports ExitInternal.
func RejectionCode(err error) (code string, exit int) {
	var classified verify.Error
	if !errors.As(err, &classified) {
		return "", ExitInternal
	}
	switch classified := classified.(type) {
	case *verify.UsageError:
		return "MALFORMED_INPUT", ExitMalformed
	case *verify.VerificationError:
		switch classified.Layer {
		case verify.LayerEnvelope:
			return "ENVELOPE_REJECTED", ExitRejected
		case verify.LayerProvenance:
			return "PROVENANCE_REJECTED", ExitRejected
		case verify.LayerQuote:
			return "QUOTE_REJECTED", ExitRejected
		case verify.LayerPolicy:
			return "POLICY_REJECTED", ExitRejected
		}
	}
	return "", ExitInternal
}

// TLSSPKIFingerprint dials host:443 and returns the SDK's canonical SPKI
// fingerprint of the presented leaf (verify.ConnectionCertFP — the same
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
	return verify.ConnectionCertFP(conn.ConnectionState())
}
