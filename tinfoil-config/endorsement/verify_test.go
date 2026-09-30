package endorsement_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"strings"
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
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/tinfoil-config/endorsement"
	f_log "github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/merkle/rfc6962"
	"golang.org/x/mod/sumdb/note"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	testScope      = "16a44d18-3387-44ce-9bfb-d77c4d27dbba"
	testOtherScope = "618b2048-f6d8-4419-a870-a8fb99a0e46b"
	testIdentity   = "/tinfoil/model-router"
	testName       = testIdentity + "/v0.0.155"
	testLogOrigin  = "rekor.test.invalid"
)

var testConfig = []byte("# Approved config bytes\nname: gpt-oss-120b\n")

type testTrust struct {
	root.BaseTrustedMaterial
	tsa *root.SigstoreTimestampingAuthority
	log *root.TransparencyLog
}

func (t testTrust) TimestampingAuthorities() []root.TimestampingAuthority {
	return []root.TimestampingAuthority{t.tsa}
}

func (t testTrust) RekorLogs() map[string]*root.TransparencyLog {
	return map[string]*root.TransparencyLog{hex.EncodeToString(t.log.ID): t.log}
}

type fixture struct {
	trust  testTrust
	key    *ecdsa.PrivateKey
	logKey *ecdsa.PrivateKey
	tsaKey *ecdsa.PrivateKey
	now    time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	newKey := func() *ecdsa.PrivateKey {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		return key
	}
	f := &fixture{key: newKey(), logKey: newKey(), tsaKey: newKey(), now: time.Now().UTC().Truncate(time.Second)}
	rootCert, rootKey, err := ca.GenerateRootCa()
	require.NoError(t, err)
	intermediate, intermediateKey, err := ca.GenerateTSAIntermediate(rootCert, rootKey)
	require.NoError(t, err)
	leaf, err := ca.GenerateTSALeafCert(f.now.Add(-time.Minute), f.tsaKey, intermediate, intermediateKey)
	require.NoError(t, err)
	f.trust.tsa = &root.SigstoreTimestampingAuthority{
		Root: rootCert, Intermediates: []*x509.Certificate{intermediate}, Leaf: leaf,
		URI: "https://tsa.test.invalid", ValidityPeriodStart: f.now.Add(-time.Hour),
	}
	logDER, err := x509.MarshalPKIXPublicKey(f.logKey.Public())
	require.NoError(t, err)
	logID := sha256.Sum256(logDER)
	f.trust.log = &root.TransparencyLog{
		BaseURL: "https://" + testLogOrigin, ID: logID[:], PublicKey: f.logKey.Public(),
		HashFunc: crypto.SHA256, SignatureHashFunc: crypto.SHA256,
		ValidityPeriodStart: f.now.Add(-time.Hour),
	}
	return f
}

func (f *fixture) policy() endorsement.Policy {
	return endorsement.Policy{Identity: testIdentity, AuditScope: testScope, Now: f.now}
}

func (f *fixture) signingKey() endorsement.SigningKey {
	return endorsement.SigningKey{PublicKey: f.key.Public(), AuditScope: testScope}
}

func (f *fixture) verifier(t *testing.T) *endorsement.Verifier {
	t.Helper()
	v, err := endorsement.NewVerifier(&f.trust, []endorsement.SigningKey{f.signingKey()})
	require.NoError(t, err)
	return v
}

func (f *fixture) timestamp(t *testing.T, input []byte, at time.Time) []byte {
	t.Helper()
	return f.timestampWithPolicy(t, input, at, asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 2})
}

func (f *fixture) timestampWithPolicy(t *testing.T, input []byte, at time.Time, policy asn1.ObjectIdentifier) []byte {
	t.Helper()
	digest := sha256.Sum256(input)
	ts := timestamp.Timestamp{
		HashAlgorithm: crypto.SHA256, HashedMessage: digest[:], Time: at,
		Policy: policy,
	}
	response, err := ts.CreateResponseWithOpts(f.trust.tsa.Leaf, f.tsaKey, crypto.SHA256)
	require.NoError(t, err)
	return response
}

func (f *fixture) statement(t *testing.T, at time.Time) []byte {
	t.Helper()
	s, err := endorsement.NewStatement(testName, testScope, testConfig)
	require.NoError(t, err)
	input, err := s.TimestampInput()
	require.NoError(t, err)
	payload, err := s.Complete(f.timestamp(t, input, at))
	require.NoError(t, err)
	return payload
}

func (f *fixture) bundle(t *testing.T, payload []byte) *protobundle.Bundle {
	t.Helper()
	message := dsse.PAE(endorsement.PayloadType, payload)
	signer, err := signature.LoadECDSASignerVerifier(f.key, crypto.SHA256)
	require.NoError(t, err)
	sig, err := signer.SignMessage(bytes.NewReader(message))
	require.NoError(t, err)
	hint, err := endorsement.KeyHint(f.key.Public())
	require.NoError(t, err)
	digest := sha256.Sum256(message)
	b := &protobundle.Bundle{
		MediaType: endorsement.BundleType,
		Content: &protobundle.Bundle_DsseEnvelope{DsseEnvelope: &protodsse.Envelope{
			Payload: payload, PayloadType: endorsement.PayloadType, Signatures: []*protodsse.Signature{{Sig: sig}},
		}},
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_PublicKey{PublicKey: &common.PublicKeyIdentifier{Hint: hint}},
		},
	}
	keyDER, err := x509.MarshalPKIXPublicKey(f.key.Public())
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
	logSigner, err := signature.LoadECDSASignerVerifier(f.logKey, crypto.SHA256)
	require.NoError(t, err)
	noteSigner, err := rekornote.NewNoteSigner(context.Background(), testLogOrigin, logSigner)
	require.NoError(t, err)
	checkpoint := f_log.Checkpoint{Origin: testLogOrigin, Size: 1, Hash: leafHash}
	signedNote, err := note.Sign(&note.Note{Text: string(checkpoint.Marshal())}, noteSigner)
	require.NoError(t, err)
	b.VerificationMaterial.TlogEntries = []*protorekor.TransparencyLogEntry{{
		LogId:             &common.LogId{KeyId: f.trust.log.ID},
		KindVersion:       &protorekor.KindVersion{Kind: "hashedrekord", Version: "0.0.2"},
		CanonicalizedBody: body,
		InclusionProof:    &protorekor.InclusionProof{TreeSize: 1, RootHash: leafHash, Checkpoint: &protorekor.Checkpoint{Envelope: string(signedNote)}},
	}}
	return b
}

func marshalBundle(t *testing.T, b *protobundle.Bundle) []byte {
	t.Helper()
	encoded, err := protojson.Marshal(b)
	require.NoError(t, err)
	return encoded
}

func TestVerifyConfigApproval(t *testing.T) {
	f := newFixture(t)
	payload := f.statement(t, f.now.Add(-time.Minute))
	b := f.bundle(t, payload)
	got, err := f.verifier(t).Verify(testConfig, marshalBundle(t, b), f.policy())
	require.NoError(t, err)
	require.Equal(t, testName, got.Name)
	require.Equal(t, testScope, got.AuditScope)
	require.Equal(t, f.now.Add(-time.Minute), got.ApprovalTime)
	require.Nil(t, b.GetVerificationMaterial().GetTimestampVerificationData())
	wantRef := sha256.Sum256(dsse.PAE(endorsement.PayloadType, payload))
	require.Equal(t, "sha256:"+hex.EncodeToString(wantRef[:]), got.Reference)

	policy := f.policy()
	policy.Revision = "v0.0.155"
	policy.Digest = got.Digest
	_, err = f.verifier(t).Verify(testConfig, marshalBundle(t, b), policy)
	require.NoError(t, err)
}

func TestVerifyPreparedRequiresAuthenticatedApprovalBeforeLogging(t *testing.T) {
	f := newFixture(t)
	b := f.bundle(t, f.statement(t, f.now))
	require.ErrorContains(t, f.verifier(t).VerifyPrepared(testConfig, marshalBundle(t, b), f.policy()), "must not contain log receipts")
	b.VerificationMaterial.TlogEntries = nil
	prepared := marshalBundle(t, b)
	require.NoError(t, f.verifier(t).VerifyPrepared(testConfig, prepared, f.policy()))
	_, err := f.verifier(t).Verify(testConfig, prepared, f.policy())
	require.Error(t, err, "preflight validation cannot replace log inclusion")

	b.GetDsseEnvelope().Signatures[0].Sig[0] ^= 1
	require.Error(t, f.verifier(t).VerifyPrepared(testConfig, marshalBundle(t, b), f.policy()), "an invalid signature must not become durable work")
}

func TestVerifyRejectsWrongPinsAndUntrustedKeys(t *testing.T) {
	f := newFixture(t)
	b := marshalBundle(t, f.bundle(t, f.statement(t, f.now)))
	for _, tc := range []struct {
		name   string
		mutate func(*endorsement.Policy)
	}{
		{"identity", func(p *endorsement.Policy) { p.Identity = "/tinfoil/other" }},
		{"scope", func(p *endorsement.Policy) { p.AuditScope = testOtherScope }},
		{"revision", func(p *endorsement.Policy) { p.Revision = "v0.0.156" }},
		{"digest", func(p *endorsement.Policy) { p.Digest = strings.Repeat("0", sha256.Size*2) }},
		{"missing clock", func(p *endorsement.Policy) { p.Now = time.Time{} }},
		{"negative age", func(p *endorsement.Policy) { p.MaxAge = -time.Second }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy := f.policy()
			tc.mutate(&policy)
			_, err := f.verifier(t).Verify(testConfig, b, policy)
			require.Error(t, err)
		})
	}
	_, err := f.verifier(t).Verify(append(bytes.Clone(testConfig), '\n'), b, f.policy())
	require.ErrorContains(t, err, "config bytes")
	other := newFixture(t)
	_, err = other.verifier(t).Verify(testConfig, b, f.policy())
	require.ErrorContains(t, err, "signer is not authorized")
}

func TestVerifyRequiresSignedApprovalAndLogInclusion(t *testing.T) {
	f := newFixture(t)
	payload := f.statement(t, f.now)
	for _, tc := range []struct {
		name   string
		mutate func(*protobundle.Bundle)
	}{
		{"signature", func(b *protobundle.Bundle) { b.GetDsseEnvelope().Signatures[0].Sig[0] ^= 1 }},
		{"checkpoint", func(b *protobundle.Bundle) {
			b.VerificationMaterial.TlogEntries[0].InclusionProof.Checkpoint.Envelope += "invalid"
		}},
		{"proof", func(b *protobundle.Bundle) {
			b.VerificationMaterial.TlogEntries[0].InclusionProof.Hashes = [][]byte{make([]byte, sha256.Size)}
		}},
		{"missing log", func(b *protobundle.Bundle) { b.VerificationMaterial.TlogEntries = nil }},
		{"legacy log", func(b *protobundle.Bundle) { b.VerificationMaterial.TlogEntries[0].KindVersion.Version = "0.0.1" }},
		{"integrated time", func(b *protobundle.Bundle) { b.VerificationMaterial.TlogEntries[0].IntegratedTime = f.now.Unix() }},
		{"unexpected outer timestamp", func(b *protobundle.Bundle) {
			b.VerificationMaterial.TimestampVerificationData = &protobundle.TimestampVerificationData{
				Rfc3161Timestamps: []*common.RFC3161SignedTimestamp{{SignedTimestamp: f.timestamp(t, b.GetDsseEnvelope().GetSignatures()[0].GetSig(), f.now)}},
			}
		}},
		{"duplicate signature", func(b *protobundle.Bundle) {
			b.GetDsseEnvelope().Signatures = append(b.GetDsseEnvelope().Signatures, b.GetDsseEnvelope().Signatures[0])
		}},
		{"unknown key", func(b *protobundle.Bundle) { b.VerificationMaterial.GetPublicKey().Hint = "untrusted" }},
		{"signing certificate", func(b *protobundle.Bundle) {
			b.VerificationMaterial.Content = &protobundle.VerificationMaterial_Certificate{Certificate: &common.X509Certificate{RawBytes: f.trust.tsa.Leaf.Raw}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := f.bundle(t, payload)
			tc.mutate(b)
			_, err := f.verifier(t).Verify(testConfig, marshalBundle(t, b), f.policy())
			require.Error(t, err)
		})
	}
}

func TestInnerTimestampBindsCompleteCore(t *testing.T) {
	f := newFixture(t)
	for _, tc := range []struct {
		name   string
		mutate func(*endorsement.Statement)
	}{
		{"name", func(s *endorsement.Statement) { s.Subject[0].Name = testIdentity + "/changed" }},
		{"timestamp on other input", func(s *endorsement.Statement) {
			s.Predicate.Freshness.RFC3161Timestamp = f.timestamp(t, []byte("other"), f.now)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := endorsement.ParseStatement(f.statement(t, f.now))
			require.NoError(t, err)
			tc.mutate(s)
			payload, err := json.Marshal(s)
			require.NoError(t, err)
			b := f.bundle(t, payload)
			_, err = f.verifier(t).Verify(testConfig, marshalBundle(t, b), f.policy())
			require.ErrorContains(t, err, "inner timestamp")
		})
	}
}

func TestFreshnessUsesInnerTimeAndInclusiveBounds(t *testing.T) {
	f := newFixture(t)
	inner := f.now.Add(-time.Minute)
	b := marshalBundle(t, f.bundle(t, f.statement(t, inner)))
	policy := f.policy()
	policy.Now = inner.Add(endorsement.DefaultMaxAge)
	_, err := f.verifier(t).Verify(testConfig, b, policy)
	require.NoError(t, err)
	policy.Now = policy.Now.Add(time.Nanosecond)
	_, err = f.verifier(t).Verify(testConfig, b, policy)
	require.ErrorContains(t, err, "too old")

	policy = f.policy()
	policy.Now = inner.Add(-endorsement.DefaultFutureSkew)
	_, err = f.verifier(t).Verify(testConfig, b, policy)
	require.NoError(t, err)
	policy.Now = policy.Now.Add(-time.Nanosecond)
	_, err = f.verifier(t).Verify(testConfig, b, policy)
	require.ErrorContains(t, err, "future")
}

func TestIgnoreFreshnessSkipsOnlyTheAgeCheck(t *testing.T) {
	f := newFixture(t)
	inner := f.now.Add(-time.Minute)
	b := marshalBundle(t, f.bundle(t, f.statement(t, inner)))
	stale := f.policy()
	stale.Now = inner.Add(endorsement.DefaultMaxAge + time.Hour)
	_, err := f.verifier(t).Verify(testConfig, b, stale)
	require.ErrorContains(t, err, "too old")

	policy := endorsement.Policy{Identity: testIdentity, AuditScope: testScope, IgnoreFreshness: true}
	verified, err := f.verifier(t).Verify(testConfig, b, policy)
	require.NoError(t, err)
	require.True(t, verified.ApprovalTime.Equal(inner))

	_, err = f.verifier(t).Verify(append(bytes.Clone(testConfig), '\n'), b, policy)
	require.ErrorContains(t, err, "config bytes")
	policy.AuditScope = testOtherScope
	_, err = f.verifier(t).Verify(testConfig, b, policy)
	require.ErrorContains(t, err, "signer is not authorized")
}

func TestUntrustedInnerTSAAndWrongPolicy(t *testing.T) {
	f := newFixture(t)
	s, err := endorsement.NewStatement(testName, testScope, testConfig)
	require.NoError(t, err)
	input, err := s.TimestampInput()
	require.NoError(t, err)
	other := newFixture(t)
	for _, response := range [][]byte{
		other.timestamp(t, input, f.now),
		f.timestampWithPolicy(t, input, f.now, asn1.ObjectIdentifier{1, 2, 3, 4}),
	} {
		payload, err := s.Complete(response)
		require.NoError(t, err)
		_, err = f.verifier(t).Verify(testConfig, marshalBundle(t, f.bundle(t, payload)), f.policy())
		require.ErrorContains(t, err, "inner timestamp")
	}
}

func TestSigningKeyRotationAllowsOverlapAndRejectsRemovedKeys(t *testing.T) {
	f := newFixture(t)
	oldKey := f.signingKey()
	oldBundle := marshalBundle(t, f.bundle(t, f.statement(t, f.now)))
	newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	f.key = newKey
	newTrust := f.signingKey()
	newBundle := marshalBundle(t, f.bundle(t, f.statement(t, f.now)))
	verifier, err := endorsement.NewVerifier(&f.trust, []endorsement.SigningKey{oldKey, newTrust})
	require.NoError(t, err)
	for _, b := range [][]byte{oldBundle, newBundle} {
		_, err := verifier.Verify(testConfig, b, f.policy())
		require.NoError(t, err)
	}
	verifier, err = endorsement.NewVerifier(&f.trust, []endorsement.SigningKey{newTrust})
	require.NoError(t, err)
	_, err = verifier.Verify(testConfig, oldBundle, f.policy())
	require.ErrorContains(t, err, "signer is not authorized")
	_, err = verifier.Verify(testConfig, newBundle, f.policy())
	require.NoError(t, err)
}
