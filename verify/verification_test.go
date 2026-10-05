package verify

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/document"
	"github.com/tinfoilsh/tinfoil-go/internal/fetch"
	"github.com/tinfoilsh/tinfoil-go/internal/sdkinfo"
	"github.com/tinfoilsh/tinfoil-go/internal/testutil"
)

func TestLiveVerificationRecordsRepoAndMetadata(t *testing.T) {
	const enclaveEnvVar, repoEnvVar = "TINFOIL_ENCLAVE", "TINFOIL_REPO"
	testutil.RequireLive(t, enclaveEnvVar, repoEnvVar)
	repo := os.Getenv(repoEnvVar)
	configRepo, _, _, err := ParseReference(repo)
	require.NoError(t, err)
	nonce, err := document.RandomNonce()
	require.NoError(t, err)
	raw, err := fetch.Document(t.Context(), os.Getenv(enclaveEnvVar), "", nonce, fetch.SDK{})
	require.NoError(t, err)
	verifier, err := NewVerifier()
	require.NoError(t, err)

	before := time.Now()
	verified, err := verifier.VerifyV3(raw, nonce, repo)
	after := time.Now()
	require.NoError(t, err)
	require.Equal(t, configRepo, verified.ConfigRepo)
	require.Equal(t, SoftwareIdentity{Name: sdkinfo.Name, Version: sdkinfo.Version()}, verified.Metadata.Verifier)
	require.Equal(t, time.UTC, verified.Metadata.VerifiedAt.Location())
	require.WithinRange(t, verified.Metadata.VerifiedAt, before, after)

	// A tag pin selects the release but is not part of the repository name.
	require.NotEmpty(t, verified.CodeTag)
	pinned, err := verifier.VerifyV3(raw, nonce, configRepo+"@"+verified.CodeTag)
	require.NoError(t, err)
	require.Equal(t, configRepo, pinned.ConfigRepo)
}
