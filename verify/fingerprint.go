package verify

import (
	"crypto/sha256"
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
