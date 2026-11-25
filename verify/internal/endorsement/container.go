package endorsement

import (
	"encoding/json/jsontext"
	"fmt"
	"slices"
	"strings"

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

	refSegmentSeparator = "/"
	refWildcard         = "*"
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
// required workflow of the required repository, at a ref that required.Ref
// matches.
func (c *Client) authenticateContainer(bundle []byte, required configendorsement.ContainerProvenance) error {
	result, _, err := c.verifyBundleForSubject(bundle, githubIdentityPattern, required.Digest, "")
	if err != nil {
		return fmt.Errorf("verifying container provenance: %w", err)
	}
	if result.Statement.Type != inTotoStatementV1 || result.Statement.PredicateType != slsaProvenanceV1 {
		return fmt.Errorf("container provenance must use SLSA v1")
	}
	// The source fields name the repository and ref that the run built. The
	// identity names the workflow file that signed, which must be that
	// repository's own file at that ref and not one called from elsewhere.
	certificate := result.Signature.Certificate
	repository := githubURLPrefix + required.Repository
	identity := repository + githubWorkflowsPath + required.Workflow + workflowRefSeparator + certificate.SourceRepositoryRef
	switch {
	case certificate.SourceRepositoryURI != repository:
		return fmt.Errorf("container provenance source repository %q is not %q", certificate.SourceRepositoryURI, repository)
	case certificate.SourceRepositoryIdentifier != required.RepositoryID:
		return fmt.Errorf("container provenance source repository ID %q is not %q", certificate.SourceRepositoryIdentifier, required.RepositoryID)
	case certificate.SubjectAlternativeName != identity:
		return fmt.Errorf("container provenance workflow identity %q is not %q", certificate.SubjectAlternativeName, identity)
	case !refMatches(required.Ref, certificate.SourceRepositoryRef):
		return fmt.Errorf("container provenance source ref %q does not match %q", certificate.SourceRepositoryRef, required.Ref)
	}
	return nil
}

// refMatches reports whether the whole of ref matches pattern, in which "*"
// stands for any run of characters, possibly empty, other than "/", and every
// other character stands for itself. It takes time bounded by the product of
// the two lengths.
func refMatches(pattern, ref string) bool {
	return slices.EqualFunc(strings.Split(pattern, refSegmentSeparator), strings.Split(ref, refSegmentSeparator), refSegmentMatches)
}

// refSegmentMatches is refMatches for one segment of each.
func refSegmentMatches(pattern, segment string) bool {
	pieces := strings.Split(pattern, refWildcard)
	first, last := pieces[0], pieces[len(pieces)-1]
	if len(pieces) == 1 {
		return segment == first
	}
	if len(segment) < len(first)+len(last) || !strings.HasPrefix(segment, first) || !strings.HasSuffix(segment, last) {
		return false
	}
	// Each piece between the first and the last is taken at its earliest
	// occurrence, which leaves the most room for those after it.
	rest := segment[len(first) : len(segment)-len(last)]
	for _, piece := range pieces[1 : len(pieces)-1] {
		_, after, found := strings.Cut(rest, piece)
		if !found {
			return false
		}
		rest = after
	}
	return true
}
