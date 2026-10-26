package verify

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
)

func TestCertPubkeyFP(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	sum := sha256.Sum256(spki)
	cert := &x509.Certificate{PublicKey: &key.PublicKey}

	fp, err := CertPubkeyFP(cert)
	require.NoError(t, err)
	require.Equal(t, hex.EncodeToString(sum[:]), fp)

	fp, err = ConnectionCertFP(tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}})
	require.NoError(t, err)
	require.Equal(t, hex.EncodeToString(sum[:]), fp)
}

func TestCertPubkeyFPRejectsMissingInput(t *testing.T) {
	var usage *UsageError

	_, err := CertPubkeyFP(nil)
	require.ErrorAs(t, err, &usage)

	_, err = CertPubkeyFP(&x509.Certificate{PublicKey: "not a key"})
	require.ErrorAs(t, err, &usage)

	_, err = ConnectionCertFP(tls.ConnectionState{})
	require.ErrorAs(t, err, &usage)
}

func TestPinTLSKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	state := tls.ConnectionState{PeerCertificates: []*x509.Certificate{{PublicKey: &key.PublicKey}}}
	fp, err := ConnectionCertFP(state)
	require.NoError(t, err)

	require.NoError(t, PinTLSKey(fp)(state))

	var rejected *VerificationError
	require.ErrorAs(t, PinTLSKey(strings.Repeat("00", 32))(state), &rejected)
	require.Equal(t, LayerPolicy, rejected.Layer)

	var usage *UsageError
	require.ErrorAs(t, PinTLSKey(fp)(tls.ConnectionState{}), &usage)
}
