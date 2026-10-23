package scope

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	configendorsement "github.com/tinfoilsh/tinfoil-go/endorsement/config"
	"github.com/tinfoilsh/tinfoil-go/internal/statement"
)

const (
	Organization = "organization"
	User         = "user"
	Validity     = 90 * 24 * time.Hour
	ClockSkew    = 5 * time.Minute
	MaxDERSize   = 16 << 10

	identityPrefix = "https://registry.tinfoil.sh/signing/v1/"
	identityParts  = 4
	serialBits     = 159
)

type Identity struct {
	OwnerKind string
	OwnerID   string
	ScopeID   string
	Namespace string
}

func (i Identity) URI() (*url.URL, error) {
	if i.OwnerKind != Organization && i.OwnerKind != User {
		return nil, fmt.Errorf("invalid registry owner kind")
	}
	for _, value := range []string{i.OwnerID, i.ScopeID} {
		id, err := uuid.Parse(value)
		if err != nil || id == uuid.Nil || id.String() != value {
			return nil, fmt.Errorf("registry owner and scope IDs must be canonical UUIDs")
		}
	}
	if err := configendorsement.ValidateIdentityComponent(i.Namespace); err != nil {
		return nil, fmt.Errorf("invalid registry namespace: %w", err)
	}
	return url.Parse(identityPrefix + strings.Join([]string{i.OwnerKind, i.OwnerID, i.ScopeID, i.Namespace}, "/"))
}

func ParseIdentity(uri *url.URL) (Identity, error) {
	var identity Identity
	if uri == nil {
		return identity, fmt.Errorf("registry scope URI is missing")
	}
	suffix, ok := strings.CutPrefix(uri.String(), identityPrefix)
	parts := strings.Split(suffix, "/")
	if !ok || len(parts) != identityParts {
		return identity, fmt.Errorf("invalid registry scope URI")
	}
	identity = Identity{OwnerKind: parts[0], OwnerID: parts[1], ScopeID: parts[2], Namespace: parts[3]}
	canonical, err := identity.URI()
	if err != nil || canonical.String() != uri.String() {
		return Identity{}, fmt.Errorf("noncanonical registry scope URI")
	}
	return identity, nil
}

func Issue(issuer *x509.Certificate, signer crypto.Signer, key crypto.PublicKey, identity Identity, now time.Time) ([]byte, error) {
	uri, err := identity.URI()
	if err != nil {
		return nil, err
	}
	hint, err := statement.KeyHint(key)
	if err != nil {
		return nil, err
	}
	if issuer == nil || signer == nil || now.IsZero() || !issuer.IsCA {
		return nil, fmt.Errorf("scope issuance requires an issuer, signer, and time")
	}
	issuerHint, err := statement.KeyHint(issuer.PublicKey)
	if err != nil {
		return nil, err
	}
	if hint == issuerHint {
		return nil, fmt.Errorf("scope signing key must differ from its issuer")
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), serialBits))
	if err != nil {
		return nil, err
	}
	serial.Add(serial, big.NewInt(1))
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: identity.ScopeID},
		NotBefore: now.Add(-ClockSkew), NotAfter: now.Add(Validity),
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		KeyUsage:           x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true, URIs: []*url.URL{uri},
	}
	if template.NotBefore.Before(issuer.NotBefore) || template.NotAfter.After(issuer.NotAfter) {
		return nil, fmt.Errorf("scope certificate exceeds issuer validity")
	}
	return x509.CreateCertificate(rand.Reader, template, issuer, key, signer)
}

type Verifier struct {
	rootKeys map[string]struct{}
}

func NewVerifier(keys []crypto.PublicKey) (*Verifier, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("registry root keys must not be empty")
	}
	v := &Verifier{rootKeys: make(map[string]struct{}, len(keys))}
	for _, key := range keys {
		hint, err := statement.KeyHint(key)
		if err != nil {
			return nil, err
		}
		if _, exists := v.rootKeys[hint]; exists {
			return nil, fmt.Errorf("duplicate registry root key")
		}
		v.rootKeys[hint] = struct{}{}
	}
	return v, nil
}

// Verify authenticates a direct scope certificate. Its issuance log proof is checked separately.
func (v *Verifier) Verify(der, issuerDER []byte, now time.Time) (*x509.Certificate, Identity, error) {
	var identity Identity
	if v == nil || now.IsZero() {
		return nil, identity, fmt.Errorf("registry verification requires root keys and time")
	}
	cert, err := ParseCertificate(der)
	if err != nil {
		return nil, identity, err
	}
	issuer, err := ParseCertificate(issuerDER)
	if err != nil {
		return nil, identity, err
	}
	hint, err := statement.KeyHint(issuer.PublicKey)
	if err != nil {
		return nil, identity, err
	}
	if _, ok := v.rootKeys[hint]; !ok {
		return nil, identity, fmt.Errorf("untrusted registry root")
	}
	if err := issuer.CheckSignatureFrom(issuer); err != nil {
		return nil, identity, fmt.Errorf("invalid registry root certificate: %w", err)
	}
	if cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage != x509.KeyUsageDigitalSignature ||
		len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageCodeSigning || len(cert.UnknownExtKeyUsage) != 0 ||
		cert.SignatureAlgorithm != x509.ECDSAWithSHA256 || cert.NotAfter.Sub(cert.NotBefore) > Validity+ClockSkew ||
		cert.NotBefore.Before(issuer.NotBefore) || cert.NotAfter.After(issuer.NotAfter) {
		return nil, identity, fmt.Errorf("invalid registry signing certificate profile")
	}
	leafHint, err := statement.KeyHint(cert.PublicKey)
	if err != nil {
		return nil, identity, err
	}
	if _, isRoot := v.rootKeys[leafHint]; isRoot {
		return nil, identity, fmt.Errorf("registry root cannot serve as a scope signing key")
	}
	if len(cert.URIs) != 1 || len(cert.DNSNames) != 0 || len(cert.EmailAddresses) != 0 || len(cert.IPAddresses) != 0 {
		return nil, identity, fmt.Errorf("registry certificate requires one scope URI")
	}
	identity, err = ParseIdentity(cert.URIs[0])
	if err != nil {
		return nil, identity, err
	}
	roots := x509.NewCertPool()
	roots.AddCert(issuer)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}}); err != nil {
		return nil, identity, fmt.Errorf("verifying registry scope certificate: %w", err)
	}
	return cert, identity, nil
}

func ParseCertificate(der []byte) (*x509.Certificate, error) {
	if len(der) == 0 || len(der) > MaxDERSize {
		return nil, fmt.Errorf("registry certificate size is outside allowed bounds")
	}
	return x509.ParseCertificate(der)
}
