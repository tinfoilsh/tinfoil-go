package provenance

import (
	in_toto "github.com/in-toto/attestation/go/v1"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

func TestAuthenticatedDigestIsCanonicalForFreshness(t *testing.T) {
	expected := testAuthenticatedArtifact()
	result := &verify.VerificationResult{
		Signature: &verify.SignatureVerificationResult{Certificate: &certificate.Summary{Extensions: certificate.Extensions{
			SourceRepositoryRef: "refs/tags/" + expected.Tag, SourceRepositoryDigest: expected.Commit,
		}}},
		Statement: &in_toto.Statement{Subject: []*in_toto.ResourceDescriptor{{Name: expected.SubjectName, Digest: map[string]string{"sha256": expected.Digest}}}},
	}
	uppercase := strings.ToUpper(expected.Digest)
	require.NoError(t, enforceSubject0Digest(result, uppercase))
	got, err := authenticatedArtifact(result, expected.Repo, expected.Tag, uppercase, "code")
	require.NoError(t, err)
	require.Equal(t, expected.Digest, got.Digest)
	require.NoError(t, validateAuthenticatedArtifact(&got))
	require.NoError(t, validateWitness(testWitness(), &got))
	require.Error(t, enforceSubject0Digest(result, strings.Repeat("ff", 32)))
}
