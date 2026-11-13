package tinfoil_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	tinfoil "github.com/tinfoilsh/tinfoil-go"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

func TestConnectionCertFP(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	sum := sha256.Sum256(spki)
	cert := &x509.Certificate{PublicKey: &key.PublicKey}

	fp, err := tinfoil.ConnectionCertFP(tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}})
	require.NoError(t, err)
	require.Equal(t, hex.EncodeToString(sum[:]), fp)

	want, err := verify.CertPubkeyFP(cert)
	require.NoError(t, err)
	require.Equal(t, want, fp)
}

func TestConnectionCertFPRejectsMissingCertificate(t *testing.T) {
	var usage *verify.UsageError
	_, err := tinfoil.ConnectionCertFP(tls.ConnectionState{})
	require.ErrorAs(t, err, &usage)
}

func TestPinTLSKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	state := tls.ConnectionState{PeerCertificates: []*x509.Certificate{{PublicKey: &key.PublicKey}}}
	fp, err := tinfoil.ConnectionCertFP(state)
	require.NoError(t, err)

	require.NoError(t, tinfoil.PinTLSKey(fp)(state))

	var rejected *verify.VerificationError
	require.ErrorAs(t, tinfoil.PinTLSKey(strings.Repeat("00", 32))(state), &rejected)
	require.Equal(t, verify.LayerPolicy, rejected.Layer)

	var usage *verify.UsageError
	require.ErrorAs(t, tinfoil.PinTLSKey(fp)(tls.ConnectionState{}), &usage)
}
