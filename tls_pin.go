package tinfoil

import (
	"crypto/tls"
	"fmt"

	"github.com/tinfoilsh/tinfoil-go/internal/transport"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

// ConnectionCertFP returns the verify.CertPubkeyFP of the leaf certificate
// that a TLS connection presented. It returns a *verify.UsageError if the
// connection presented no certificate.
func ConnectionCertFP(c tls.ConnectionState) (string, error) {
	return transport.ConnectionCertFP(c)
}

// PinTLSKey returns a tls.Config VerifyConnection callback that accepts only a
// connection whose leaf certificate carries the public key fingerprint fp, in
// the form that verify.Verification.TLSPublicKeyFP reports. It adds to the
// certificate checks that the tls.Config performs; it doesn't replace them.
//
// A connection that presents no certificate fails with a *verify.UsageError,
// and one whose key doesn't match fails with a *verify.VerificationError at
// verify.LayerPolicy.
func PinTLSKey(fp string) func(tls.ConnectionState) error {
	return func(c tls.ConnectionState) error {
		got, err := ConnectionCertFP(c)
		if err != nil {
			return err
		}
		if got != fp {
			return &verify.VerificationError{Layer: verify.LayerPolicy, Err: fmt.Errorf("TLS key %s does not match the attested key %s", got, fp)}
		}
		return nil
	}
}
