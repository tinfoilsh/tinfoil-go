package crl

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCheckExtensions(t *testing.T) {
	now := time.Date(2026, time.November, 13, 0, 0, 0, 0, time.UTC)
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "CRL test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	require.NoError(t, err)
	issuer, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	unknown := asn1.ObjectIdentifier{1, 2, 3, 4}
	for _, tc := range []struct {
		name       string
		extensions []pkix.Extension
		entry      bool
		valid      bool
	}{
		{name: "complete", valid: true},
		{name: "noncritical hint", extensions: []pkix.Extension{{Id: unknown, Value: []byte{5, 0}}}, valid: true},
		{name: "critical list extension", extensions: []pkix.Extension{{Id: unknown, Critical: true, Value: []byte{5, 0}}}},
		{name: "critical entry extension", extensions: []pkix.Extension{{Id: unknown, Critical: true, Value: []byte{5, 0}}}, entry: true},
		{name: "delta", extensions: []pkix.Extension{{Id: deltaCRLIndicator, Critical: true, Value: []byte{2, 1, 1}}}},
		{name: "noncritical delta", extensions: []pkix.Extension{{Id: deltaCRLIndicator, Value: []byte{2, 1, 1}}}},
		{name: "scoped", extensions: []pkix.Extension{{Id: issuingDistributionPoint, Critical: true, Value: []byte{0x30, 0}}}},
		{name: "noncritical scoped", extensions: []pkix.Extension{{Id: issuingDistributionPoint, Value: []byte{0x30, 0}}}},
		{name: "indirect entry", extensions: []pkix.Extension{{Id: certificateIssuer, Value: []byte{0x30, 0}}}, entry: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			list := &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: now, NextUpdate: now.Add(time.Hour)}
			if tc.entry {
				list.RevokedCertificateEntries = []x509.RevocationListEntry{{SerialNumber: big.NewInt(2), RevocationTime: now, ExtraExtensions: tc.extensions}}
			} else {
				list.ExtraExtensions = tc.extensions
			}
			der, err := x509.CreateRevocationList(rand.Reader, list, issuer, key)
			require.NoError(t, err)
			parsed, err := x509.ParseRevocationList(der)
			require.NoError(t, err)
			require.NoError(t, parsed.CheckSignatureFrom(issuer))
			err = CheckExtensions(parsed)
			if tc.valid {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, "unsupported CRL extension")
			}
		})
	}
}
