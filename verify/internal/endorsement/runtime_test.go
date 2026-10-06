package endorsement

import (
	"strings"
	"testing"

	in_toto "github.com/in-toto/attestation/go/v1"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/stretchr/testify/require"
)

func TestRuntimeSubjectMustBeUniqueAndMatchNameAndDigest(t *testing.T) {
	const name = "tinfoil-inference-v0.15.0-manifest.json"
	digest := strings.Repeat("ab", 32)
	matching := &in_toto.ResourceDescriptor{Name: name, Digest: map[string]string{"sha256": digest}}
	other := &in_toto.ResourceDescriptor{Name: "other-artifact", Digest: map[string]string{"sha256": strings.Repeat("cd", 32)}}
	result := func(subjects ...*in_toto.ResourceDescriptor) *verify.VerificationResult {
		return &verify.VerificationResult{Statement: &in_toto.Statement{Subject: subjects}}
	}
	require.NoError(t, enforceArtifactSubject(result(other, matching), name, digest))
	uppercase := &in_toto.ResourceDescriptor{Name: name, Digest: map[string]string{"sha256": strings.ToUpper(digest)}}
	require.NoError(t, enforceArtifactSubject(result(uppercase), name, digest))
	for label, value := range map[string]*verify.VerificationResult{
		"missing":      result(other),
		"duplicate":    result(matching, matching),
		"wrong digest": result(&in_toto.ResourceDescriptor{Name: name, Digest: other.Digest}),
		"null subject": result(nil, matching),
		"no statement": {},
	} {
		t.Run(label, func(t *testing.T) { require.Error(t, enforceArtifactSubject(value, name, digest)) })
	}
	require.Error(t, enforceArtifactSubject(result(other, matching), "", digest), "legacy provenance still requires subject zero")
}
