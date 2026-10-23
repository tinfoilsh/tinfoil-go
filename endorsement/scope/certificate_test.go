package scope_test

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/endorsement/scope"
	"github.com/tinfoilsh/tinfoil-go/internal/sigstoretest"
)

var testIdentity = scope.Identity{
	OwnerKind: scope.Organization, OwnerID: "c5cbb595-6271-45a0-a851-65c67173ee8a",
	ScopeID: "36c405e9-30df-4fe7-85d5-c1a509484541", Namespace: "acme",
}

func TestScopeCertificateProfile(t *testing.T) {
	f := sigstoretest.New(t)
	leaf := sigstoretest.New(t).Key
	material := f.Scope(t, leaf.Public(), testIdentity)
	v, err := scope.NewVerifier([]crypto.PublicKey{f.Key.Public()})
	require.NoError(t, err)
	cert, identity, err := v.Verify(material.Certificate, material.Issuer, f.Now)
	require.NoError(t, err)
	require.Equal(t, testIdentity, identity)
	require.Equal(t, leaf.Public(), cert.PublicKey)
	require.Equal(t, f.Now.Add(scope.Validity), cert.NotAfter)
	_, _, err = v.Verify(material.Certificate, material.Issuer, cert.NotAfter.Add(time.Second))
	require.ErrorContains(t, err, "expired")
	_, _, err = v.Verify(material.Certificate, material.Issuer, cert.NotBefore.Add(-time.Second))
	require.ErrorContains(t, err, "not yet valid")
	untrusted, err := scope.NewVerifier([]crypto.PublicKey{leaf.Public()})
	require.NoError(t, err)
	_, _, err = untrusted.Verify(material.Certificate, material.Issuer, f.Now)
	require.ErrorContains(t, err, "untrusted registry root")

	issuer, err := scope.ParseCertificate(material.Issuer)
	require.NoError(t, err)
	for name, mutate := range map[string]func(*x509.Certificate){
		"CA":                 func(c *x509.Certificate) { c.IsCA = true; c.KeyUsage |= x509.KeyUsageCertSign },
		"TLS purpose":        func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} },
		"extra key usage":    func(c *x509.Certificate) { c.KeyUsage |= x509.KeyUsageKeyEncipherment },
		"unbounded lifetime": func(c *x509.Certificate) { c.NotAfter = f.Now.Add(scope.Validity + time.Hour) },
		"missing scope":      func(c *x509.Certificate) { c.URIs = nil },
		"multiple scopes":    func(c *x509.Certificate) { c.URIs = append(c.URIs, c.URIs[0]) },
		"unknown critical extension": func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: []byte{5, 0}}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			cert, err := scope.ParseCertificate(material.Certificate)
			require.NoError(t, err)
			mutate(cert)
			der, err := x509.CreateCertificate(rand.Reader, cert, issuer, leaf.Public(), f.Key)
			require.NoError(t, err)
			_, _, err = v.Verify(der, material.Issuer, f.Now)
			require.Error(t, err)
		})
	}
}

func TestScopeIdentityRejectsAmbiguousNamespaces(t *testing.T) {
	uri, err := testIdentity.URI()
	require.NoError(t, err)
	for _, raw := range []string{
		strings.Replace(uri.String(), "/acme", "/acme/other", 1),
		strings.Replace(uri.String(), "/acme", "/%61cme", 1),
		strings.Replace(uri.String(), testIdentity.OwnerID, strings.ToUpper(testIdentity.OwnerID), 1),
		strings.Replace(uri.String(), "registry.tinfoil.sh", "registry.tinfoil.sh.example", 1),
		uri.String() + "?scope=other",
	} {
		parsed, err := url.Parse(raw)
		require.NoError(t, err)
		_, err = scope.ParseIdentity(parsed)
		require.Error(t, err, raw)
	}
}
