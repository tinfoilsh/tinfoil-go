package freshness_test

import (
	"crypto"
	"encoding/json/v2"
	"strings"
	"testing"
	"time"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	common "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/freshness"
	"github.com/tinfoilsh/tinfoil-go/internal/approvaltest"
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

func statement(t *testing.T, f *approvaltest.Fixture, a freshness.Artifact, at time.Time) []byte {
	t.Helper()
	s, err := freshness.NewStatement(a)
	require.NoError(t, err)
	input, err := s.TimestampInput()
	require.NoError(t, err)
	payload, err := s.Complete(f.Timestamp(t, input, at))
	require.NoError(t, err)
	return payload
}

func verifier(t *testing.T, f *approvaltest.Fixture) *freshness.Verifier {
	t.Helper()
	v, err := freshness.NewVerifier(&f.Trust, []crypto.PublicKey{f.Key.Public()})
	require.NoError(t, err)
	return v
}

func TestVerifyArtifactApproval(t *testing.T) {
	f := approvaltest.New(t)
	for _, kind := range []string{freshness.KindPlatform, freshness.KindRuntime} {
		t.Run(kind, func(t *testing.T) {
			a := artifact(kind)
			at := f.Now.Add(-time.Minute)
			payload := statement(t, f, a, at)
			b := f.Bundle(t, payload)
			got, err := verifier(t, f).Verify(approvaltest.MarshalBundle(t, b), freshness.Policy{Artifact: a, Now: f.Now})
			require.NoError(t, err)
			require.Equal(t, a, got.Artifact)
			require.Equal(t, at, got.ApprovalTime)
			ref, err := freshness.EndorsementReference(payload)
			require.NoError(t, err)
			require.Equal(t, ref, got.Reference)
		})
	}
}

func TestVerifyRejectsWrongArtifactAndKey(t *testing.T) {
	f := approvaltest.New(t)
	a := artifact(freshness.KindRuntime)
	b := approvaltest.MarshalBundle(t, f.Bundle(t, statement(t, f, a, f.Now)))
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
			_, err := verifier(t, f).Verify(b, freshness.Policy{Artifact: pin, Now: f.Now})
			require.Error(t, err)
		})
	}
	other := approvaltest.New(t)
	v, err := freshness.NewVerifier(&f.Trust, []crypto.PublicKey{other.Key.Public()})
	require.NoError(t, err)
	_, err = v.Verify(b, freshness.Policy{Artifact: a, Now: f.Now})
	require.ErrorContains(t, err, "untrusted approval signing key")
}

func TestVerifyRequiresSignatureTimestampAndInclusion(t *testing.T) {
	f := approvaltest.New(t)
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
			_, err := verifier(t, f).Verify(approvaltest.MarshalBundle(t, b), freshness.Policy{Artifact: a, Now: f.Now})
			require.Error(t, err)
		})
	}
	for _, untrusted := range []bool{false, true} {
		s, err := freshness.ParseStatement(payload)
		require.NoError(t, err)
		if untrusted {
			input, err := s.TimestampInput()
			require.NoError(t, err)
			s.Predicate.Freshness.RFC3161Timestamp = approvaltest.New(t).Timestamp(t, input, f.Now)
		} else {
			s.Predicate.Freshness.RFC3161Timestamp = f.Timestamp(t, []byte("different core"), f.Now)
		}
		altered, err := json.Marshal(s)
		require.NoError(t, err)
		_, err = verifier(t, f).Verify(approvaltest.MarshalBundle(t, f.Bundle(t, altered)), freshness.Policy{Artifact: a, Now: f.Now})
		require.ErrorContains(t, err, "inner timestamp")
	}
}

func TestApprovalAgeUsesInnerTime(t *testing.T) {
	f := approvaltest.New(t)
	a := artifact(freshness.KindRuntime)
	b := approvaltest.MarshalBundle(t, f.Bundle(t, statement(t, f, a, f.Now)))
	for _, tc := range []struct {
		name   string
		now    time.Time
		accept bool
	}{
		{"age boundary", f.Now.Add(freshness.DefaultMaxAge), true},
		{"expired", f.Now.Add(freshness.DefaultMaxAge + time.Nanosecond), false},
		{"future boundary", f.Now.Add(-freshness.DefaultFutureSkew), true},
		{"future", f.Now.Add(-freshness.DefaultFutureSkew - time.Nanosecond), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := verifier(t, f).Verify(b, freshness.Policy{Artifact: a, Now: tc.now})
			if tc.accept {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestTimestampBindsEveryArtifactField(t *testing.T) {
	f := approvaltest.New(t)
	a := artifact(freshness.KindRuntime)
	s, err := freshness.NewStatement(a)
	require.NoError(t, err)
	input, err := s.TimestampInput()
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(string(input), "tinfoil-artifact-freshness/v1\x00"))
	response := f.Timestamp(t, input, f.Now)
	_, err = verifier(t, f).VerifyTimestamp(input, response, freshness.Policy{Artifact: a, Now: f.Now})
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
