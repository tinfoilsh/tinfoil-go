package config

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"slices"
	"time"
)

const uriGeneralNameTag = 6

var subjectAlternativeNameOID = asn1.ObjectIdentifier{2, 5, 29, 17}

// VerifySigningCertificate authenticates the registry identity at at. The caller
// must independently authenticate that time when verifying a signed endorsement.
func VerifySigningCertificate(certificateDER, issuerDER []byte, roots []crypto.PublicKey, at time.Time) (*x509.Certificate, *x509.Certificate, error) {
	if at.IsZero() || len(certificateDER) == 0 || len(certificateDER) > MaxCertificateSize || len(issuerDER) == 0 || len(issuerDER) > MaxCertificateSize {
		return nil, nil, fmt.Errorf("signing certificate requires a time and bounded certificate bytes")
	}
	cert, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		return nil, nil, err
	}
	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		return nil, nil, err
	}
	issuerHint, err := KeyHint(issuer.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	trusted := make([]string, 0, len(roots))
	for _, root := range roots {
		hint, err := KeyHint(root)
		if err != nil {
			return nil, nil, err
		}
		trusted = append(trusted, hint)
	}
	if !slices.Contains(trusted, issuerHint) {
		return nil, nil, fmt.Errorf("untrusted registry root")
	}
	if err := issuer.CheckSignatureFrom(issuer); err != nil {
		return nil, nil, fmt.Errorf("invalid registry root certificate: %w", err)
	}
	if cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage != x509.KeyUsageDigitalSignature ||
		len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageCodeSigning || len(cert.UnknownExtKeyUsage) != 0 ||
		cert.SignatureAlgorithm != x509.ECDSAWithSHA256 || cert.NotAfter.Sub(cert.NotBefore) > CertificateValidity ||
		cert.NotBefore.Before(issuer.NotBefore) || cert.NotAfter.After(issuer.NotAfter) || len(cert.Subject.Names) != 0 ||
		len(cert.URIs) != 1 || len(cert.DNSNames) != 0 || len(cert.IPAddresses) != 0 || len(cert.EmailAddresses) != 0 {
		return nil, nil, fmt.Errorf("invalid config signing certificate profile")
	}
	if err := ValidateRegistryID(cert.URIs[0].String()); err != nil {
		return nil, nil, err
	}
	for _, extension := range cert.Extensions {
		if !extension.Id.Equal(subjectAlternativeNameOID) {
			continue
		}
		var names []asn1.RawValue
		rest, err := asn1.Unmarshal(extension.Value, &names)
		if !extension.Critical || err != nil || len(rest) != 0 || len(names) != 1 || names[0].Class != asn1.ClassContextSpecific || names[0].Tag != uriGeneralNameTag || names[0].IsCompound || string(names[0].Bytes) != cert.URIs[0].String() {
			return nil, nil, fmt.Errorf("registry identity requires exactly one critical URI SAN")
		}
	}
	hint, err := KeyHint(cert.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	if slices.Contains(trusted, hint) {
		return nil, nil, fmt.Errorf("registry root cannot serve as a config signing key")
	}
	pool := x509.NewCertPool()
	pool.AddCert(issuer)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: at, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}}); err != nil {
		return nil, nil, fmt.Errorf("verifying config signing certificate: %w", err)
	}
	return cert, issuer, nil
}
