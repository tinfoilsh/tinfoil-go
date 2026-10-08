package endorsement_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json/v2"
	"strings"
	"testing"
	"time"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	common "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/stretchr/testify/require"
	configendorsement "github.com/tinfoilsh/tinfoil-go/endorsement/config"
	"github.com/tinfoilsh/tinfoil-go/endorsement/freshness"
	"github.com/tinfoilsh/tinfoil-go/internal/sigstoretest"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/endorsement"
)

const (
	testIdentity = "/tinfoil/model-router"
	testName     = testIdentity + "/v0.0.155"
)

var testConfig = []byte("# Approved config bytes\nname: gpt-oss-120b\n")

type fixture struct{ *sigstoretest.Fixture }

func newFixture(t *testing.T) *fixture { return &fixture{sigstoretest.New(t)} }

func (f *fixture) policy() endorsement.ConfigPolicy {
	return endorsement.ConfigPolicy{Identity: testIdentity, Now: f.Now}
}

func (f *fixture) verifier(t *testing.T) *endorsement.ConfigVerifier {
	t.Helper()
	v, err := endorsement.NewConfigVerifier(&f.Trust, []crypto.PublicKey{f.Key.Public()})
	require.NoError(t, err)
	return v
}

func (f *fixture) statement(t *testing.T, at time.Time) []byte {
	t.Helper()
	s, err := configendorsement.NewStatement(testName, testConfig)
	require.NoError(t, err)
	input, err := s.TimestampInput()
	require.NoError(t, err)
	payload, err := s.Complete(f.Timestamp(t, input, at))
	require.NoError(t, err)
	return payload
}

func TestVerifyConfigApproval(t *testing.T) {
	f := newFixture(t)
	payload := f.statement(t, f.Now.Add(-time.Minute))
	b := f.Bundle(t, payload)
	got, err := f.verifier(t).Verify(testConfig, sigstoretest.MarshalBundle(t, b), f.policy())
	require.NoError(t, err)
	require.Equal(t, testName, got.Name)
	require.Equal(t, f.Now.Add(-time.Minute), got.ApprovalTime)
	require.Nil(t, b.GetVerificationMaterial().GetTimestampVerificationData())
	wantRef := sha256.Sum256(dsse.PAE(configendorsement.PayloadType, payload))
	require.Equal(t, "sha256:"+hex.EncodeToString(wantRef[:]), got.Reference)

	policy := f.policy()
	policy.Revision = "v0.0.155"
	policy.Digest = got.Digest
	_, err = f.verifier(t).Verify(testConfig, sigstoretest.MarshalBundle(t, b), policy)
	require.NoError(t, err)
}

func TestPolicyValidatePins(t *testing.T) {
	policy := endorsement.ConfigPolicy{Identity: testIdentity}
	require.NoError(t, policy.ValidatePins())
	policy.Revision = "v0.0.155"
	policy.Digest = strings.Repeat("ab", sha256.Size)
	require.NoError(t, policy.ValidatePins())
	for name, mutate := range map[string]func(*endorsement.ConfigPolicy){
		"identity": func(p *endorsement.ConfigPolicy) { p.Identity = "/tinfoil" },
		"revision": func(p *endorsement.ConfigPolicy) { p.Revision = "../v1" },
		"digest":   func(p *endorsement.ConfigPolicy) { p.Digest = strings.ToUpper(p.Digest) },
	} {
		t.Run(name, func(t *testing.T) {
			invalid := policy
			mutate(&invalid)
			require.Error(t, invalid.ValidatePins())
		})
	}
}

func TestApprovalVerificationRequiresTSATrustEvenWhenIgnoringAge(t *testing.T) {
	f := newFixture(t)
	trust, err := root.NewTrustedRoot(root.TrustedRootMediaType01, nil, nil, nil, f.Trust.RekorLogs())
	require.NoError(t, err)
	keys := []crypto.PublicKey{f.Key.Public()}
	configs, err := endorsement.NewConfigVerifier(trust, keys)
	require.NoError(t, err)
	approvals, err := endorsement.NewFreshnessVerifier(trust, keys)
	require.NoError(t, err)
	configBundle := sigstoretest.MarshalBundle(t, f.Bundle(t, f.statement(t, f.Now)))
	a := artifact(freshness.KindRuntime)
	approvalBundle := sigstoretest.MarshalBundle(t, f.Bundle(t, statement(t, f.Fixture, a, f.Now)))
	for _, ignore := range []bool{false, true} {
		policy := f.policy()
		policy.IgnoreFreshness = ignore
		_, err := configs.Verify(testConfig, configBundle, policy)
		require.ErrorContains(t, err, "no trusted timestamp authority")
		_, err = approvals.Verify(approvalBundle, endorsement.FreshnessPolicy{Artifact: a, Now: f.Now, IgnoreFreshness: ignore})
		require.ErrorContains(t, err, "no trusted timestamp authority")
	}
}

func TestVerifyRejectsWrongPinsAndUntrustedKeys(t *testing.T) {
	f := newFixture(t)
	b := sigstoretest.MarshalBundle(t, f.Bundle(t, f.statement(t, f.Now)))
	for _, tc := range []struct {
		name   string
		mutate func(*endorsement.ConfigPolicy)
	}{
		{"identity", func(p *endorsement.ConfigPolicy) { p.Identity = "/tinfoil/other" }},
		{"revision", func(p *endorsement.ConfigPolicy) { p.Revision = "v0.0.156" }},
		{"digest", func(p *endorsement.ConfigPolicy) { p.Digest = strings.Repeat("0", sha256.Size*2) }},
		{"missing clock", func(p *endorsement.ConfigPolicy) { p.Now = time.Time{} }},
		{"negative age", func(p *endorsement.ConfigPolicy) { p.MaxAge = -time.Second }},
		{"negative skew", func(p *endorsement.ConfigPolicy) { p.FutureSkew = -time.Second }},
		{"archived negative age", func(p *endorsement.ConfigPolicy) { p.IgnoreFreshness = true; p.MaxAge = -time.Second }},
		{"archived negative skew", func(p *endorsement.ConfigPolicy) { p.IgnoreFreshness = true; p.FutureSkew = -time.Second }},
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
	require.ErrorContains(t, err, "untrusted approval signing key")
}

func TestVerifyRequiresSignedApprovalAndLogInclusion(t *testing.T) {
	f := newFixture(t)
	payload := f.statement(t, f.Now)
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
		{"integrated time", func(b *protobundle.Bundle) { b.VerificationMaterial.TlogEntries[0].IntegratedTime = f.Now.Unix() }},
		{"unexpected outer timestamp", func(b *protobundle.Bundle) {
			b.VerificationMaterial.TimestampVerificationData = &protobundle.TimestampVerificationData{
				Rfc3161Timestamps: []*common.RFC3161SignedTimestamp{{SignedTimestamp: f.Timestamp(t, b.GetDsseEnvelope().GetSignatures()[0].GetSig(), f.Now)}},
			}
		}},
		{"duplicate signature", func(b *protobundle.Bundle) {
			b.GetDsseEnvelope().Signatures = append(b.GetDsseEnvelope().Signatures, b.GetDsseEnvelope().Signatures[0])
		}},
		{"unknown key", func(b *protobundle.Bundle) { b.VerificationMaterial.GetPublicKey().Hint = "untrusted" }},
		{"signing certificate", func(b *protobundle.Bundle) {
			b.VerificationMaterial.Content = &protobundle.VerificationMaterial_Certificate{Certificate: &common.X509Certificate{RawBytes: f.Trust.TSA.Leaf.Raw}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := f.Bundle(t, payload)
			tc.mutate(b)
			_, err := f.verifier(t).Verify(testConfig, sigstoretest.MarshalBundle(t, b), f.policy())
			require.Error(t, err)
		})
	}
}

func TestInnerTimestampBindsCompleteCore(t *testing.T) {
	f := newFixture(t)
	for _, tc := range []struct {
		name   string
		mutate func(*configendorsement.Statement)
	}{
		{"name", func(s *configendorsement.Statement) { s.Subject[0].Name = testIdentity + "/changed" }},
		{"timestamp on other input", func(s *configendorsement.Statement) {
			s.Predicate.Freshness.RFC3161Timestamp = f.Timestamp(t, []byte("other"), f.Now)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := configendorsement.ParseStatement(f.statement(t, f.Now))
			require.NoError(t, err)
			tc.mutate(s)
			payload, err := json.Marshal(s)
			require.NoError(t, err)
			b := f.Bundle(t, payload)
			_, err = f.verifier(t).Verify(testConfig, sigstoretest.MarshalBundle(t, b), f.policy())
			require.ErrorContains(t, err, "inner timestamp")
		})
	}
}

func TestFreshnessUsesInnerTimeAndInclusiveBounds(t *testing.T) {
	f := newFixture(t)
	inner := f.Now.Add(-time.Minute)
	b := sigstoretest.MarshalBundle(t, f.Bundle(t, f.statement(t, inner)))
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
	inner := f.Now.Add(-time.Minute)
	b := sigstoretest.MarshalBundle(t, f.Bundle(t, f.statement(t, inner)))
	stale := f.policy()
	stale.Now = inner.Add(endorsement.DefaultMaxAge + time.Hour)
	_, err := f.verifier(t).Verify(testConfig, b, stale)
	require.ErrorContains(t, err, "too old")

	policy := endorsement.ConfigPolicy{Identity: testIdentity, IgnoreFreshness: true}
	verified, err := f.verifier(t).Verify(testConfig, b, policy)
	require.NoError(t, err)
	require.True(t, verified.ApprovalTime.Equal(inner))

	_, err = f.verifier(t).Verify(append(bytes.Clone(testConfig), '\n'), b, policy)
	require.ErrorContains(t, err, "config bytes")
	_, err = newFixture(t).verifier(t).Verify(testConfig, b, policy)
	require.ErrorContains(t, err, "untrusted approval signing key")
}

func TestUntrustedInnerTSAAndWrongPolicy(t *testing.T) {
	f := newFixture(t)
	s, err := configendorsement.NewStatement(testName, testConfig)
	require.NoError(t, err)
	input, err := s.TimestampInput()
	require.NoError(t, err)
	other := newFixture(t)
	for _, response := range [][]byte{
		other.Timestamp(t, input, f.Now),
		f.TimestampWithPolicy(t, input, f.Now, asn1.ObjectIdentifier{1, 2, 3, 4}),
	} {
		payload, err := s.Complete(response)
		require.NoError(t, err)
		_, err = f.verifier(t).Verify(testConfig, sigstoretest.MarshalBundle(t, f.Bundle(t, payload)), f.policy())
		require.ErrorContains(t, err, "inner timestamp")
	}
}

func TestSigningKeyRotationAllowsOverlapAndRejectsRemovedKeys(t *testing.T) {
	f := newFixture(t)
	oldKey := f.Key.Public()
	oldBundle := sigstoretest.MarshalBundle(t, f.Bundle(t, f.statement(t, f.Now)))
	newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	f.Key = newKey
	newTrust := f.Key.Public()
	newBundle := sigstoretest.MarshalBundle(t, f.Bundle(t, f.statement(t, f.Now)))
	verifier, err := endorsement.NewConfigVerifier(&f.Trust, []crypto.PublicKey{oldKey, newTrust})
	require.NoError(t, err)
	for _, b := range [][]byte{oldBundle, newBundle} {
		_, err := verifier.Verify(testConfig, b, f.policy())
		require.NoError(t, err)
	}
	verifier, err = endorsement.NewConfigVerifier(&f.Trust, []crypto.PublicKey{newTrust})
	require.NoError(t, err)
	_, err = verifier.Verify(testConfig, oldBundle, f.policy())
	require.ErrorContains(t, err, "untrusted approval signing key")
	_, err = verifier.Verify(testConfig, newBundle, f.policy())
	require.NoError(t, err)
}
