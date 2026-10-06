package endorsement_test

import (
	"crypto"
	"encoding/json/v2"
	"strings"
	"testing"
	"time"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	common "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/endorsement/freshness"
	"github.com/tinfoilsh/tinfoil-go/internal/sigstoretest"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/endorsement"
)

func artifact(kind string) freshness.Artifact {
	a := freshness.Artifact{Kind: kind, Tag: "v1.2.3", Digest: strings.Repeat("ab", 32)}
	if kind == freshness.KindPlatform {
		a.Repo, a.Name = freshness.PlatformRepo, freshness.PlatformName
	} else {
		a.Repo, a.Name = freshness.RuntimeRepo, freshness.RuntimeName(a.Tag)
	}
	return a
}

func statement(t *testing.T, f *sigstoretest.Fixture, a freshness.Artifact, at time.Time) []byte {
	t.Helper()
	s, err := freshness.NewStatement(a)
	require.NoError(t, err)
	input, err := s.TimestampInput()
	require.NoError(t, err)
	payload, err := s.Complete(f.Timestamp(t, input, at))
	require.NoError(t, err)
	return payload
}

func verifier(t *testing.T, f *sigstoretest.Fixture) *endorsement.FreshnessVerifier {
	t.Helper()
	v, err := endorsement.NewFreshnessVerifier(&f.Trust, []crypto.PublicKey{f.Key.Public()})
	require.NoError(t, err)
	return v
}

func TestVerifyArtifactApproval(t *testing.T) {
	f := sigstoretest.New(t)
	for _, kind := range []string{freshness.KindPlatform, freshness.KindRuntime} {
		t.Run(kind, func(t *testing.T) {
			a := artifact(kind)
			at := f.Now.Add(-time.Minute)
			payload := statement(t, f, a, at)
			b := f.Bundle(t, payload)
			got, err := verifier(t, f).Verify(sigstoretest.MarshalBundle(t, b), endorsement.FreshnessPolicy{Artifact: a, Now: f.Now})
			require.NoError(t, err)
			require.Equal(t, a, got.Artifact)
			require.Equal(t, at, got.ApprovalTime)
			ref, err := freshness.EndorsementReference(payload)
			require.NoError(t, err)
			require.Equal(t, ref, got.Reference)
		})
	}
}

func TestUninitializedVerifierReturnsError(t *testing.T) {
	f := sigstoretest.New(t)
	a := artifact(freshness.KindRuntime)
	policy := endorsement.FreshnessPolicy{Artifact: a, Now: f.Now}
	payload := statement(t, f, a, f.Now)
	bundle := sigstoretest.MarshalBundle(t, f.Bundle(t, payload))
	s, err := freshness.ParseStatement(payload)
	require.NoError(t, err)
	input, err := s.TimestampInput()
	require.NoError(t, err)
	for name, v := range map[string]*endorsement.FreshnessVerifier{
		"nil":  nil,
		"zero": {},
	} {
		t.Run(name+"/approval", func(t *testing.T) {
			got, err := v.Verify(bundle, policy)
			require.ErrorContains(t, err, "uninitialized freshness verifier")
			require.Nil(t, got)
		})
		t.Run(name+"/timestamp", func(t *testing.T) {
			got, err := v.VerifyTimestamp(input, s.Predicate.Freshness.RFC3161Timestamp, policy)
			require.ErrorContains(t, err, "uninitialized freshness verifier")
			require.True(t, got.IsZero())
		})
	}
}

func TestVerifyRejectsWrongArtifactAndKey(t *testing.T) {
	f := sigstoretest.New(t)
	a := artifact(freshness.KindRuntime)
	b := sigstoretest.MarshalBundle(t, f.Bundle(t, statement(t, f, a, f.Now)))
	for name, mutate := range map[string]func(*freshness.Artifact){
		"kind":   func(a *freshness.Artifact) { *a = artifact(freshness.KindPlatform) },
		"repo":   func(a *freshness.Artifact) { a.Repo = "other/cvmimage" },
		"tag":    func(a *freshness.Artifact) { a.Tag = "v1.2.4"; a.Name = freshness.RuntimeName(a.Tag) },
		"name":   func(a *freshness.Artifact) { a.Name = "other.json" },
		"digest": func(a *freshness.Artifact) { a.Digest = strings.Repeat("cd", 32) },
	} {
		t.Run(name, func(t *testing.T) {
			pin := a
			mutate(&pin)
			_, err := verifier(t, f).Verify(b, endorsement.FreshnessPolicy{Artifact: pin, Now: f.Now})
			require.Error(t, err)
		})
	}
	other := sigstoretest.New(t)
	v, err := endorsement.NewFreshnessVerifier(&f.Trust, []crypto.PublicKey{other.Key.Public()})
	require.NoError(t, err)
	_, err = v.Verify(b, endorsement.FreshnessPolicy{Artifact: a, Now: f.Now})
	require.ErrorContains(t, err, "untrusted approval signing key")
}

func TestVerifyRequiresSignatureTimestampAndInclusion(t *testing.T) {
	f := sigstoretest.New(t)
	a := artifact(freshness.KindPlatform)
	payload := statement(t, f, a, f.Now)
	for name, mutate := range map[string]func(*protobundle.Bundle){
		"signature": func(b *protobundle.Bundle) { b.GetDsseEnvelope().Signatures[0].Sig[0] ^= 1 },
		"inclusion": func(b *protobundle.Bundle) { b.VerificationMaterial.TlogEntries = nil },
		"checkpoint": func(b *protobundle.Bundle) {
			b.VerificationMaterial.TlogEntries[0].InclusionProof.Checkpoint.Envelope = "invalid"
		},
		"outer timestamp": func(b *protobundle.Bundle) {
			b.VerificationMaterial.TimestampVerificationData = &protobundle.TimestampVerificationData{Rfc3161Timestamps: []*common.RFC3161SignedTimestamp{{SignedTimestamp: []byte("untrusted")}}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			b := f.Bundle(t, payload)
			mutate(b)
			_, err := verifier(t, f).Verify(sigstoretest.MarshalBundle(t, b), endorsement.FreshnessPolicy{Artifact: a, Now: f.Now})
			require.Error(t, err)
		})
	}
	for _, untrusted := range []bool{false, true} {
		s, err := freshness.ParseStatement(payload)
		require.NoError(t, err)
		if untrusted {
			input, err := s.TimestampInput()
			require.NoError(t, err)
			s.Predicate.Freshness.RFC3161Timestamp = sigstoretest.New(t).Timestamp(t, input, f.Now)
		} else {
			s.Predicate.Freshness.RFC3161Timestamp = f.Timestamp(t, []byte("different core"), f.Now)
		}
		altered, err := json.Marshal(s)
		require.NoError(t, err)
		_, err = verifier(t, f).Verify(sigstoretest.MarshalBundle(t, f.Bundle(t, altered)), endorsement.FreshnessPolicy{Artifact: a, Now: f.Now})
		require.ErrorContains(t, err, "inner timestamp")
	}
}

func TestApprovalAgeUsesInnerTime(t *testing.T) {
	f := sigstoretest.New(t)
	a := artifact(freshness.KindRuntime)
	b := sigstoretest.MarshalBundle(t, f.Bundle(t, statement(t, f, a, f.Now)))
	for _, tc := range []struct {
		name   string
		now    time.Time
		accept bool
	}{
		{"missing clock", time.Time{}, false},
		{"age boundary", f.Now.Add(endorsement.DefaultMaxAge), true},
		{"expired", f.Now.Add(endorsement.DefaultMaxAge + time.Nanosecond), false},
		{"future boundary", f.Now.Add(-endorsement.DefaultFutureSkew), true},
		{"future", f.Now.Add(-endorsement.DefaultFutureSkew - time.Nanosecond), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := verifier(t, f).Verify(b, endorsement.FreshnessPolicy{Artifact: a, Now: tc.now})
			if tc.accept {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
	for _, policy := range []endorsement.FreshnessPolicy{
		{Artifact: a, Now: f.Now, MaxAge: -time.Second},
		{Artifact: a, Now: f.Now, FutureSkew: -time.Second},
	} {
		_, err := verifier(t, f).Verify(b, policy)
		require.ErrorContains(t, err, "nonnegative age and skew")
	}
}

func TestTimestampBindsEveryArtifactField(t *testing.T) {
	f := sigstoretest.New(t)
	a := artifact(freshness.KindRuntime)
	s, err := freshness.NewStatement(a)
	require.NoError(t, err)
	input, err := s.TimestampInput()
	require.NoError(t, err)
	const core = `{"_type":"https://in-toto.io/Statement/v1","predicate":{"kind":"runtime","repo":"tinfoilsh/cvmimage","tag":"v1.2.3"},"predicateType":"https://tinfoil.sh/predicate/artifact-freshness/v1","subject":[{"digest":{"sha256":"abababababababababababababababababababababababababababababababab"},"name":"tinfoil-inference-v1.2.3-manifest.json"}]}`
	require.Equal(t, "tinfoil-artifact-freshness/v1\x00"+core, string(input))
	response := f.Timestamp(t, input, f.Now)
	_, err = verifier(t, f).VerifyTimestamp(input, response, endorsement.FreshnessPolicy{Artifact: a, Now: f.Now})
	require.NoError(t, err)
	s.Subject[0].Digest["sha256"] = strings.Repeat("cd", 32)
	_, err = s.Complete(response)
	require.ErrorContains(t, err, "does not match")
	for _, badTag := range []string{"v1.2", "1.2.3", "v1.2.3/other", "v1.2.3+build"} {
		a.Tag = badTag
		a.Name = freshness.RuntimeName(badTag)
		_, err := freshness.NewStatement(a)
		require.Error(t, err)
	}
}
