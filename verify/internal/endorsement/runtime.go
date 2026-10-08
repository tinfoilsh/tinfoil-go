package endorsement

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/tinfoilsh/tinfoil-go/document/collateral"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/runtime"
)

const slsaProvenanceV1 = "https://slsa.dev/provenance/v1"

type Runtime struct {
	AuthenticatedArtifact
	Manifest *runtime.Manifest
}

func (c *Client) AuthenticateRuntime(material collateral.Runtime, expected collateral.RuntimeReference) (*Runtime, error) {
	if material.RuntimeReference != expected {
		return nil, fmt.Errorf("runtime collateral does not match the endorsed config's runtime pin")
	}
	manifest, err := runtime.ParseManifest(material.Manifest, expected)
	if err != nil {
		return nil, err
	}
	subject := "tinfoil-inference-" + expected.Tag + "-manifest.json"
	identity := githubWorkflowIdentityPattern(collateral.RuntimeRepo, `release\.yml`, `refs/tags/`+regexp.QuoteMeta(expected.Tag))
	result, _, err := c.verifyBundleForSubject(material.Bundle, identity, expected.Digest, subject)
	if err != nil {
		return nil, fmt.Errorf("verifying runtime provenance: %w", err)
	}
	if result.Statement.Type != inTotoStatementV1 || result.Statement.PredicateType != slsaProvenanceV1 {
		return nil, fmt.Errorf("runtime provenance must use SLSA v1")
	}
	authenticated, err := authenticatedArtifact(result, expected.Repo, expected.Tag, expected.Digest, "runtime")
	if err != nil {
		return nil, err
	}
	authenticated.SubjectName = subject
	return &Runtime{AuthenticatedArtifact: authenticated, Manifest: manifest}, nil
}

func enforceArtifactSubject(result *verify.VerificationResult, name, digest string) error {
	if name == "" {
		return enforceSubject0Digest(result, digest)
	}
	if result == nil || result.Statement == nil {
		return fmt.Errorf("runtime provenance has no statement")
	}
	matches := 0
	for _, subject := range result.Statement.Subject {
		if subject == nil {
			return fmt.Errorf("runtime provenance contains a null subject")
		}
		if subject.Name != name {
			continue
		}
		if !strings.EqualFold(subject.Digest["sha256"], digest) {
			return fmt.Errorf("runtime provenance subject digest does not match")
		}
		matches++
	}
	if matches != 1 {
		return fmt.Errorf("runtime provenance requires exactly one matching manifest subject")
	}
	return nil
}
