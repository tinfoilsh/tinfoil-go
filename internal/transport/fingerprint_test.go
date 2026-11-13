package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

func TestConnectionCertFP(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	sum := sha256.Sum256(spki)
	cert := &x509.Certificate{PublicKey: &key.PublicKey}

	fp, err := ConnectionCertFP(tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}})
	require.NoError(t, err)
	require.Equal(t, hex.EncodeToString(sum[:]), fp)

	want, err := verify.CertPubkeyFP(cert)
	require.NoError(t, err)
	require.Equal(t, want, fp)
}

func TestConnectionCertFPRejectsMissingCertificate(t *testing.T) {
	var usage *verify.UsageError
	_, err := ConnectionCertFP(tls.ConnectionState{})
	require.ErrorAs(t, err, &usage)
}
