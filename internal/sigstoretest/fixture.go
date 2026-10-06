// Package sigstoretest builds signed TSA and Rekor fixtures for approval tests.
package sigstoretest

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json/jsontext"
	"math/big"
	"testing"
	"time"

	"github.com/digitorus/timestamp"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	common "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	rekor "github.com/sigstore/rekor-tiles/v2/pkg/generated/protobuf"
	rekornote "github.com/sigstore/rekor-tiles/v2/pkg/note"
	"github.com/sigstore/rekor-tiles/v2/pkg/types/hashedrekord"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/internal/statement"
	f_log "github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/merkle/rfc6962"
	"golang.org/x/mod/sumdb/note"
	"google.golang.org/protobuf/encoding/protojson"
)

const logOrigin = "rekor.test.invalid"

type Trust struct {
	root.BaseTrustedMaterial
	TSA *root.SigstoreTimestampingAuthority
	Log *root.TransparencyLog
}

func (t Trust) TimestampingAuthorities() []root.TimestampingAuthority {
	return []root.TimestampingAuthority{t.TSA}
}

func (t Trust) RekorLogs() map[string]*root.TransparencyLog {
	return map[string]*root.TransparencyLog{hex.EncodeToString(t.Log.ID): t.Log}
}

type Fixture struct {
	Trust  Trust
	Key    *ecdsa.PrivateKey
	LogKey *ecdsa.PrivateKey
	TSAKey *ecdsa.PrivateKey
	Now    time.Time
}

func New(t *testing.T) *Fixture {
	t.Helper()
	newKey := func() *ecdsa.PrivateKey {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		return key
	}
	f := &Fixture{Key: newKey(), LogKey: newKey(), TSAKey: newKey(), Now: time.Now().UTC().Truncate(time.Second)}
	createCert := func(template, parent *x509.Certificate, key *ecdsa.PublicKey, signer *ecdsa.PrivateKey) *x509.Certificate {
		der, err := x509.CreateCertificate(rand.Reader, template, parent, key, signer)
		require.NoError(t, err)
		cert, err := x509.ParseCertificate(der)
		require.NoError(t, err)
		return cert
	}
	const rootSerial, leafSerial = 1, 2
	rootKey := newKey()
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(rootSerial), Subject: pkix.Name{CommonName: "test timestamp root"},
		NotBefore: f.Now.Add(-time.Hour), NotAfter: f.Now.Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
	}
	rootCert := createCert(rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	ekuOID := asn1.ObjectIdentifier{2, 5, 29, 37}
	timestampingOID := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
	eku, err := asn1.Marshal([]asn1.ObjectIdentifier{timestampingOID})
	require.NoError(t, err)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(leafSerial), Subject: pkix.Name{CommonName: "test timestamp signer"},
		NotBefore: f.Now.Add(-time.Minute), NotAfter: f.Now.Add(time.Hour),
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{{Id: ekuOID, Critical: true, Value: eku}},
	}
	leaf := createCert(leafTemplate, rootCert, &f.TSAKey.PublicKey, rootKey)
	f.Trust.TSA = &root.SigstoreTimestampingAuthority{
		Root: rootCert, Leaf: leaf,
		URI: "https://tsa.test.invalid", ValidityPeriodStart: f.Now.Add(-time.Hour),
	}
	logDER, err := x509.MarshalPKIXPublicKey(f.LogKey.Public())
	require.NoError(t, err)
	logID := sha256.Sum256(logDER)
	f.Trust.Log = &root.TransparencyLog{
		BaseURL: "https://" + logOrigin, ID: logID[:], PublicKey: f.LogKey.Public(),
		HashFunc: crypto.SHA256, SignatureHashFunc: crypto.SHA256,
		ValidityPeriodStart: f.Now.Add(-time.Hour),
	}
	return f
}

func (f *Fixture) Timestamp(t *testing.T, input []byte, at time.Time) []byte {
	t.Helper()
	return f.TimestampWithPolicy(t, input, at, asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 2})
}

func (f *Fixture) TimestampWithPolicy(t *testing.T, input []byte, at time.Time, policy asn1.ObjectIdentifier) []byte {
	t.Helper()
	digest := sha256.Sum256(input)
	ts := timestamp.Timestamp{
		HashAlgorithm: crypto.SHA256, HashedMessage: digest[:], Time: at,
		Policy: policy,
	}
	response, err := ts.CreateResponseWithOpts(f.Trust.TSA.Leaf, f.TSAKey, crypto.SHA256)
	require.NoError(t, err)
	return response
}

func (f *Fixture) Bundle(t *testing.T, payload []byte) *protobundle.Bundle {
	t.Helper()
	message := dsse.PAE(statement.PayloadType, payload)
	signer, err := signature.LoadECDSASignerVerifier(f.Key, crypto.SHA256)
	require.NoError(t, err)
	sig, err := signer.SignMessage(bytes.NewReader(message))
	require.NoError(t, err)
	hint, err := statement.KeyHint(f.Key.Public())
	require.NoError(t, err)
	digest := sha256.Sum256(message)
	b := &protobundle.Bundle{
		MediaType: statement.BundleType,
		Content: &protobundle.Bundle_DsseEnvelope{DsseEnvelope: &protodsse.Envelope{
			Payload: payload, PayloadType: statement.PayloadType, Signatures: []*protodsse.Signature{{Sig: sig}},
		}},
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_PublicKey{PublicKey: &common.PublicKeyIdentifier{Hint: hint}},
		},
	}
	keyDER, err := x509.MarshalPKIXPublicKey(f.Key.Public())
	require.NoError(t, err)
	algorithms, err := signature.NewAlgorithmRegistryConfig([]common.PublicKeyDetails{common.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256})
	require.NoError(t, err)
	entry, err := hashedrekord.ToLogEntry(&rekor.HashedRekordRequestV002{
		Digest: digest[:],
		Signature: &rekor.Signature{Content: sig, Verifier: &rekor.Verifier{
			KeyDetails: common.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,
			Verifier:   &rekor.Verifier_PublicKey{PublicKey: &rekor.PublicKey{RawBytes: keyDER}},
		}},
	}, algorithms)
	require.NoError(t, err)
	entryJSON, err := protojson.Marshal(entry)
	require.NoError(t, err)
	body := jsontext.Value(entryJSON)
	require.NoError(t, body.Canonicalize())
	leafHash := rfc6962.DefaultHasher.HashLeaf(body)
	logSigner, err := signature.LoadECDSASignerVerifier(f.LogKey, crypto.SHA256)
	require.NoError(t, err)
	noteSigner, err := rekornote.NewNoteSigner(context.Background(), logOrigin, logSigner)
	require.NoError(t, err)
	checkpoint := f_log.Checkpoint{Origin: logOrigin, Size: 1, Hash: leafHash}
	signedNote, err := note.Sign(&note.Note{Text: string(checkpoint.Marshal())}, noteSigner)
	require.NoError(t, err)
	b.VerificationMaterial.TlogEntries = []*protorekor.TransparencyLogEntry{{
		LogId:             &common.LogId{KeyId: f.Trust.Log.ID},
		KindVersion:       &protorekor.KindVersion{Kind: "hashedrekord", Version: "0.0.2"},
		CanonicalizedBody: body,
		InclusionProof:    &protorekor.InclusionProof{TreeSize: 1, RootHash: leafHash, Checkpoint: &protorekor.Checkpoint{Envelope: string(signedNote)}},
	}}
	return b
}

func MarshalBundle(t *testing.T, b *protobundle.Bundle) []byte {
	t.Helper()
	encoded, err := protojson.Marshal(b)
	require.NoError(t, err)
	return encoded
}
