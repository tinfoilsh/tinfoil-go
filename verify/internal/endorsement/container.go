package endorsement

import (
	"encoding/json/jsontext"
	"fmt"

	configendorsement "github.com/tinfoilsh/tinfoil-go/endorsement/config"
)

const (
	// githubIdentityPattern accepts every GitHub signing identity. The
	// identity of a container build is compared as text once its bundle
	// verifies.
	githubIdentityPattern = `^https://github\.com/`
	githubURLPrefix       = "https://github.com/"
	githubWorkflowsPath   = "/.github/workflows/"
	workflowRefSeparator  = "@"
)

// AuthenticateContainers verifies the build of every container image for
// which config requires one. attestation returns the Sigstore bundle that a
// document carries for the image with a lowercase hex SHA-256 digest.
func (c *Client) AuthenticateContainers(config []byte, attestation func(digest string) (jsontext.Value, error)) error {
	required, err := configendorsement.ContainerProvenanceFromConfig(config)
	if err != nil {
		return err
	}
	for _, requirement := range required {
		bundle, err := attestation(requirement.Digest)
		if err != nil {
			return err
		}
		if err := c.authenticateContainer(bundle, requirement); err != nil {
			return fmt.Errorf("container image sha256:%s: %w", requirement.Digest, err)
		}
	}
	return nil
}

// authenticateContainer verifies that bundle is a SLSA build attestation of
// the image with required.Digest, signed on a GitHub-hosted runner by the
// required workflow of the required repository, at the required ref and
// source commit.
func (c *Client) authenticateContainer(bundle []byte, required configendorsement.ContainerProvenance) error {
	result, _, err := c.verifyBundleForSubject(bundle, githubIdentityPattern, required.Digest, "")
	if err != nil {
		return fmt.Errorf("verifying container provenance: %w", err)
	}
	if result.Statement.Type != inTotoStatementV1 || result.Statement.PredicateType != slsaProvenanceV1 {
		return fmt.Errorf("container provenance must use SLSA v1")
	}
	// The source fields name the repository, ref and commit that the run
	// built. The identity names the workflow file that signed, which must be
	// that repository's own file at that ref and not one called from
	// elsewhere.
	certificate := result.Signature.Certificate
	repository := githubURLPrefix + required.Repository
	identity := repository + githubWorkflowsPath + required.Workflow + workflowRefSeparator + required.Ref
	switch {
	case certificate.SourceRepositoryURI != repository:
		return fmt.Errorf("container provenance source repository %q is not %q", certificate.SourceRepositoryURI, repository)
	case certificate.SourceRepositoryIdentifier != required.RepositoryID:
		return fmt.Errorf("container provenance source repository ID %q is not %q", certificate.SourceRepositoryIdentifier, required.RepositoryID)
	case certificate.SubjectAlternativeName != identity:
		return fmt.Errorf("container provenance workflow identity %q is not %q", certificate.SubjectAlternativeName, identity)
	case certificate.SourceRepositoryRef != required.Ref:
		return fmt.Errorf("container provenance source ref %q is not %q", certificate.SourceRepositoryRef, required.Ref)
	case certificate.SourceRepositoryDigest != required.Commit:
		return fmt.Errorf("container provenance source commit %q is not %q", certificate.SourceRepositoryDigest, required.Commit)
	}
	return nil
}
