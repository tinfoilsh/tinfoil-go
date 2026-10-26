package verify

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
)

// CertPubkeyFP returns the SPKI SHA-256 fingerprint of a certificate's public
// key (any key type), in the form TLSPublicKeyFP reports.
func CertPubkeyFP(cert *x509.Certificate) (string, error) {
	if cert == nil {
		return "", &UsageError{Err: errors.New("no certificate")}
	}
	spki, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return "", &UsageError{Err: fmt.Errorf("marshaling public key: %w", err)}
	}
	hash := sha256.Sum256(spki)
	return hex.EncodeToString(hash[:]), nil
}

// ConnectionCertFP returns the CertPubkeyFP of the leaf certificate a TLS
// connection presented.
func ConnectionCertFP(c tls.ConnectionState) (string, error) {
	if len(c.PeerCertificates) == 0 {
		return "", &UsageError{Err: errors.New("no peer certificates")}
	}
	return CertPubkeyFP(c.PeerCertificates[0])
}

// PinTLSKey returns a tls.Config VerifyConnection callback that accepts only a
// connection whose leaf certificate carries the public key fingerprint fp, in
// the form TLSPublicKeyFP reports. It adds to the certificate checks the
// tls.Config performs; it doesn't replace them.
func PinTLSKey(fp string) func(tls.ConnectionState) error {
	return func(c tls.ConnectionState) error {
		got, err := ConnectionCertFP(c)
		if err != nil {
			return err
		}
		if got != fp {
			return &VerificationError{Layer: LayerPolicy, Err: fmt.Errorf("TLS key %s does not match the attested key %s", got, fp)}
		}
		return nil
	}
}
