package endorsement

import (
	"os"
	"regexp"
	"testing"

	in_toto "github.com/in-toto/attestation/go/v1"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/stretchr/testify/require"

	configendorsement "github.com/tinfoilsh/tinfoil-go/endorsement/config"
	"github.com/tinfoilsh/tinfoil-go/internal/testutil"
)

// The recorded bundle is the published build attestation of this image.
const (
	recordedContainerRepository = "tinfoilsh/measure-image-action"
	recordedContainerDigest     = "85306e3ab312a2d80466e901081e855cc53f21c4802c638f861e6ef31ba4f5d1"
	recordedContainerCommit     = "01a05df207140a8e8e1d2cd26028ab7c51dad9d1"
	recordedContainerRef        = "refs/tags/build-v0.14.2"
)

func recordedContainerRequirement() configendorsement.ContainerProvenance {
	return configendorsement.ContainerProvenance{
		Container: "app", Digest: recordedContainerDigest,
		Repository: recordedContainerRepository, RepositoryID: "924941172",
		Workflow: "build.yml", Ref: "refs/tags/build-v*",
	}
}

func TestAuthenticateContainer(t *testing.T) {
	bundle, err := os.ReadFile("testdata/container-provenance-bundle.json")
	require.NoError(t, err)
	client := testClient(t)

	container, err := client.AuthenticateContainer(bundle, recordedContainerRequirement())
	require.NoError(t, err)
	require.Equal(t, &Container{
		Digest: recordedContainerDigest, Repository: recordedContainerRepository,
		Workflow: "build.yml", Ref: recordedContainerRef, Commit: recordedContainerCommit,
	}, container)

	for name, change := range map[string]func(*configendorsement.ContainerProvenance){
		"another image":         func(r *configendorsement.ContainerProvenance) { r.Digest = "00" + r.Digest[2:] },
		"another repository":    func(r *configendorsement.ContainerProvenance) { r.Repository = "tinfoilsh/cvmimage" },
		"repository prefix":     func(r *configendorsement.ContainerProvenance) { r.Repository = "tinfoilsh/measure-image" },
		"another repository ID": func(r *configendorsement.ContainerProvenance) { r.RepositoryID = "902195777" },
		"another workflow":      func(r *configendorsement.ContainerProvenance) { r.Workflow = "release.yml" },
		"workflow prefix":       func(r *configendorsement.ContainerProvenance) { r.Workflow = "build.ym" },
		"another tag series":    func(r *configendorsement.ContainerProvenance) { r.Ref = "refs/tags/v*" },
		"exact other tag":       func(r *configendorsement.ContainerProvenance) { r.Ref = "refs/tags/build-v0.14.3" },
		"branch":                func(r *configendorsement.ContainerProvenance) { r.Ref = "refs/heads/main" },
	} {
		t.Run(name, func(t *testing.T) {
			required := recordedContainerRequirement()
			change(&required)
			_, err := client.AuthenticateContainer(bundle, required)
			require.Error(t, err)
		})
	}
}

func TestLiveAuthenticateContainer(t *testing.T) {
	testutil.RequireLive(t)
	bundle, err := fetchAttestationBundle(recordedContainerRepository, recordedContainerDigest)
	require.NoError(t, err)
	container, err := testClient(t).AuthenticateContainer(bundle, recordedContainerRequirement())
	require.NoError(t, err)
	require.Equal(t, recordedContainerCommit, container.Commit)
}

func TestContainerSourceMustBeTheRequiredRepository(t *testing.T) {
	required := recordedContainerRequirement()
	result := func(change func(*certificate.Extensions, *in_toto.Statement)) *verify.VerificationResult {
		extensions := certificate.Extensions{
			SourceRepositoryURI:        githubRepositoryURLPrefix + recordedContainerRepository,
			SourceRepositoryIdentifier: required.RepositoryID,
			SourceRepositoryRef:        recordedContainerRef,
			SourceRepositoryDigest:     recordedContainerCommit,
		}
		statement := &in_toto.Statement{Type: inTotoStatementV1, PredicateType: slsaProvenanceV1}
		change(&extensions, statement)
		return &verify.VerificationResult{
			Signature: &verify.SignatureVerificationResult{Certificate: &certificate.Summary{Extensions: extensions}},
			Statement: statement,
		}
	}
	_, err := authenticatedContainer(result(func(*certificate.Extensions, *in_toto.Statement) {}), required, refPattern(required.Ref))
	require.NoError(t, err)

	for name, tt := range map[string]struct {
		change    func(*certificate.Extensions, *in_toto.Statement)
		wantError string
	}{
		// A workflow in another repository can call the required workflow
		// file, which then signs with its own identity.
		"called from another repository": {func(e *certificate.Extensions, _ *in_toto.Statement) {
			e.SourceRepositoryURI = githubRepositoryURLPrefix + "attacker/fork"
		}, "source repository"},
		"recreated repository":  {func(e *certificate.Extensions, _ *in_toto.Statement) { e.SourceRepositoryIdentifier = "1" }, "source repository ID"},
		"missing repository ID": {func(e *certificate.Extensions, _ *in_toto.Statement) { e.SourceRepositoryIdentifier = "" }, "source repository ID"},
		"pull request ref":      {func(e *certificate.Extensions, _ *in_toto.Statement) { e.SourceRepositoryRef = "refs/pull/7/merge" }, "source ref"},
		"nested tag": {func(e *certificate.Extensions, _ *in_toto.Statement) {
			e.SourceRepositoryRef = "refs/tags/build-v1/extra"
		}, "source ref"},
		"no commit": {func(e *certificate.Extensions, _ *in_toto.Statement) { e.SourceRepositoryDigest = "" }, "Git commit"},
		"another predicate": {func(_ *certificate.Extensions, s *in_toto.Statement) {
			s.PredicateType = "https://spdx.dev/Document/v2.3"
		}, "SLSA v1"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := authenticatedContainer(result(tt.change), required, refPattern(required.Ref))
			require.ErrorContains(t, err, tt.wantError)
		})
	}
	_, err = authenticatedContainer(&verify.VerificationResult{}, required, refPattern(required.Ref))
	require.Error(t, err)
}

func TestContainerRefPattern(t *testing.T) {
	const prefix = "https://github.com/tinfoilsh/inference/.github/workflows/containers.yml@"
	identity := func(ref string) *regexp.Regexp {
		return regexp.MustCompile(githubWorkflowIdentityPattern("tinfoilsh/inference", regexp.QuoteMeta("containers.yml"), refPattern(ref)))
	}
	for _, tt := range []struct {
		pattern, ref string
		want         bool
	}{
		{"refs/tags/vllm-v*", "refs/tags/vllm-v0.34.0", true},
		{"refs/tags/vllm-v*", "refs/tags/vllm-v", true},
		{"refs/tags/vllm-v*", "refs/tags/omni-v0.34.0", false},
		{"refs/tags/vllm-v*", "refs/tags/vllm-v0/34", false},
		{"refs/tags/vllm-v*", "refs/heads/vllm-v0.34.0", false},
		{"refs/tags/vllm-v*", "refs/tags/vllm-v0.34.0@refs/heads/main", false},
		{"refs/tags/v1.2.3", "refs/tags/v1.2.3", true},
		{"refs/tags/v1.2.3", "refs/tags/v1x2x3", false},
		{"refs/heads/main", "refs/heads/main", true},
		{"refs/heads/main", "refs/heads/maintenance", false},
		{"refs/heads/release/*", "refs/heads/release/2026", true},
		{"refs/heads/release/*", "refs/heads/release/2026/hotfix", false},
	} {
		require.Equal(t, tt.want, identity(tt.pattern).MatchString(prefix+tt.ref), "%s against %s", tt.pattern, tt.ref)
	}
}
