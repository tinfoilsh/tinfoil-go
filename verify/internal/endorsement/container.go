package endorsement

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/sigstore/sigstore-go/pkg/verify"

	configendorsement "github.com/tinfoilsh/tinfoil-go/endorsement/config"
)

const (
	githubRepositoryURLPrefix = "https://github.com/"
	// refWildcard is the pattern character a container requirement uses for
	// any run of characters within one ref segment.
	refWildcard        = "*"
	refWildcardPattern = `[^/@]*`
)

// Container is a container image whose build was authenticated against the
// requirement its config declares.
type Container struct {
	Digest     string
	Repository string
	Workflow   string
	Ref        string
	Commit     string
}

// AuthenticateContainer verifies that bundle is a SLSA build attestation for
// the required image digest, signed by the required workflow of the required
// repository on a GitHub-hosted runner.
func (c *Client) AuthenticateContainer(bundle []byte, required configendorsement.ContainerProvenance) (*Container, error) {
	ref := refPattern(required.Ref)
	identity := githubWorkflowIdentityPattern(required.Repository, regexp.QuoteMeta(required.Workflow), ref)
	result, _, err := c.verifyBundleForSubject(bundle, identity, required.Digest, "")
	if err != nil {
		return nil, fmt.Errorf("verifying container provenance: %w", err)
	}
	return authenticatedContainer(result, required, ref)
}

func authenticatedContainer(result *verify.VerificationResult, required configendorsement.ContainerProvenance, ref string) (*Container, error) {
	if result == nil || result.Statement == nil || result.Signature == nil || result.Signature.Certificate == nil {
		return nil, fmt.Errorf("container provenance has no statement or signing certificate")
	}
	if result.Statement.Type != inTotoStatementV1 || result.Statement.PredicateType != slsaProvenanceV1 {
		return nil, fmt.Errorf("container provenance must use SLSA v1")
	}
	// The signing identity names the workflow file that ran, which a workflow
	// in another repository can call. The source fields name the repository
	// and ref that triggered the run.
	certificate := result.Signature.Certificate
	if certificate.SourceRepositoryURI != githubRepositoryURLPrefix+required.Repository {
		return nil, fmt.Errorf("container provenance source repository %q does not match %q", certificate.SourceRepositoryURI, required.Repository)
	}
	if certificate.SourceRepositoryIdentifier != required.RepositoryID {
		return nil, fmt.Errorf("container provenance source repository ID does not match the required repository")
	}
	matched, err := regexp.MatchString("^"+ref+"$", certificate.SourceRepositoryRef)
	if err != nil {
		return nil, err
	}
	if !matched {
		return nil, fmt.Errorf("container provenance source ref %q does not match %q", certificate.SourceRepositoryRef, required.Ref)
	}
	if !gitCommitRE.MatchString(certificate.SourceRepositoryDigest) {
		return nil, fmt.Errorf("container provenance source digest is not a lowercase Git commit")
	}
	return &Container{
		Digest: required.Digest, Repository: required.Repository, Workflow: required.Workflow,
		Ref: certificate.SourceRepositoryRef, Commit: certificate.SourceRepositoryDigest,
	}, nil
}

// refPattern converts a requirement's ref pattern into a regular expression
// fragment.
func refPattern(ref string) string {
	literals := strings.Split(ref, refWildcard)
	for index, literal := range literals {
		literals[index] = regexp.QuoteMeta(literal)
	}
	return strings.Join(literals, refWildcardPattern)
}
