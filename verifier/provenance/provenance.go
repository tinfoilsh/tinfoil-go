// Package provenance verifies Sigstore-signed reference values against the
// pinned Tinfoil workflow identities, producing verified value types: the
// code measurement (with its declared VM shape) and the
// platform-endorsements artifact.
package provenance

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"google.golang.org/protobuf/encoding/protojson"

	in_toto "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/tinfoilsh/tinfoil-go/verifier/policy"
	"github.com/tinfoilsh/tinfoil-go/verifier/measurement"
)

const (
	oidcIssuer = "https://token.actions.githubusercontent.com"

	// platformEndorsementsRepo publishes the platform-endorsements artifact.
	platformEndorsementsRepo = "tinfoilsh/platform-endorsements"

	// platformEndorsementsIdentity is the only signing certificate identity
	// accepted for the platform-endorsements artifact: the tag-triggered
	// build workflow of the publisher repo. Dots are escaped and the pattern
	// is anchored at both ends so no other workflow path, ref type, or
	// trailing SAN content can match.
	platformEndorsementsIdentity = "^https://github\\.com/" + platformEndorsementsRepo +
		"/\\.github/workflows/build\\.yml@refs/tags/v[0-9][^@]*$"
)

type Client struct {
	trustRoot *root.TrustedRoot
}

// NewClientFromJSON builds a client from a Sigstore trusted-root document
// (conventionally the SDK's embedded copy, refreshed by the rootfetch tool).
func NewClientFromJSON(trustRootJSON []byte) (*Client, error) {
	trustRoot, err := root.NewTrustedRootFromJSON(trustRootJSON)
	if err != nil {
		return nil, fmt.Errorf("parsing trust root: %w", err)
	}
	return &Client{trustRoot: trustRoot}, nil
}

// repoNameRE matches a GitHub "owner/name" repository slug.
var repoNameRE = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)

// signingIdentity returns the anchored SAN regex accepted for artifacts
// signed from repo: one workflow file directly under the repository's
// .github/workflows directory, run from a tag ref. The repository name is
// validated and escaped so it cannot alter the pattern.
func signingIdentity(repo string) (string, error) {
	if !repoNameRE.MatchString(repo) {
		return "", fmt.Errorf("invalid repository name %q", repo)
	}
	return "^https://github\\.com/" + regexp.QuoteMeta(repo) +
		"/\\.github/workflows/[^/@]+@refs/tags/[^@]+$", nil
}

func (c *Client) VerifyBundle(bundleJSON []byte, repo, hexDigest string) (*verify.VerificationResult, error) {
	sanRegex, err := signingIdentity(repo)
	if err != nil {
		return nil, err
	}
	return c.verifyBundleWithIdentity(bundleJSON, sanRegex, hexDigest)
}

// verifyBundleWithIdentity verifies a Sigstore bundle against an explicit
// signing certificate SAN regex.
func (c *Client) verifyBundleWithIdentity(bundleJSON []byte, sanRegex, hexDigest string) (*verify.VerificationResult, error) {
	if c.trustRoot == nil {
		return nil, fmt.Errorf("trust root is not set")
	}

	var b bundle.Bundle
	b.Bundle = new(protobundle.Bundle)
	if err := b.UnmarshalJSON(bundleJSON); err != nil {
		return nil, fmt.Errorf("parsing bundle: %w", err)
	}
	if err := rejectLegacyBundleFormat(b.Bundle); err != nil {
		return nil, err
	}
	if err := requireExactlyOneDSSESignature(b.Bundle); err != nil {
		return nil, err
	}

	verifier, err := verify.NewSignedEntityVerifier(
		c.trustRoot,
		verify.WithSignedCertificateTimestamps(1),
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1),
	)
	if err != nil {
		return nil, fmt.Errorf("creating signed entity verifier: %w", err)
	}

	sanMatcher, err := verify.NewSANMatcher("", sanRegex)
	if err != nil {
		return nil, fmt.Errorf("creating SAN matcher: %w", err)
	}
	issuerMatcher, err := verify.NewIssuerMatcher(oidcIssuer, "")
	if err != nil {
		return nil, fmt.Errorf("creating issuer matcher: %w", err)
	}
	// runner_environment comes from the OIDC token, so a workflow retargeted
	// to self-hosted (operator-controlled) infrastructure cannot claim
	// github-hosted.
	certID, err := verify.NewCertificateIdentity(
		sanMatcher,
		issuerMatcher,
		certificate.Extensions{RunnerEnvironment: "github-hosted"},
	)
	if err != nil {
		return nil, fmt.Errorf("creating certificate identity: %w", err)
	}

	digest, err := hex.DecodeString(hexDigest)
	if err != nil {
		return nil, fmt.Errorf("decoding hex digest: %w", err)
	}
	result, err := verifier.Verify(
		&b,
		verify.NewPolicy(
			verify.WithArtifactDigest("sha256", digest),
			verify.WithCertificateIdentity(certID),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("verifying: %w", err)
	}

	// SPEC §5.2: reject duplicate-log SCTs. sigstore-go dedups SCTs by log ID
	// rather than rejecting, so a leaf cert carrying two SCTs from the same CT
	// log would pass; reject it here, matching the rs/js SDKs.
	vm := b.Bundle.GetVerificationMaterial()
	var leafCertDER []byte
	if c := vm.GetCertificate(); c != nil && len(c.GetRawBytes()) > 0 {
		leafCertDER = c.GetRawBytes()
	} else if chain := vm.GetX509CertificateChain(); chain != nil && len(chain.GetCertificates()) > 0 {
		leafCertDER = chain.GetCertificates()[0].GetRawBytes()
	}
	if err := checkDuplicateSCTLogs(leafCertDER); err != nil {
		return nil, err
	}

	// SPEC §5.4: WithArtifactDigest matched the digest against ANY subject in
	// the in-toto statement; narrow that to subject[0] only, matching the SPEC
	// and the rs/py/js SDKs.
	if err := enforceSubject0Digest(result, hexDigest); err != nil {
		return nil, err
	}

	return result, nil
}

// enforceSubject0Digest applies SPEC §5.4: only the FIRST in-toto subject is
// checked against the expected artifact digest. sigstore-go's WithArtifactDigest
// matches the digest against ANY subject in the statement (valid generic in-toto
// semantics — a Statement's subject array may legitimately list several
// artifacts), so we re-check subject[0] specifically here to honor the SPEC and
// match the other Tinfoil SDKs (rs/py/js), which all key on subject[0]. Digests
// are compared case-insensitively (lowercase-normalized per SPEC §7.3).
func enforceSubject0Digest(result *verify.VerificationResult, expectedDigest string) error {
	if result == nil || result.Statement == nil {
		return fmt.Errorf("verification result has no in-toto statement")
	}
	if len(result.Statement.Subject) == 0 {
		return fmt.Errorf("in-toto statement has no subject")
	}
	got := result.Statement.Subject[0].Digest["sha256"]
	if !strings.EqualFold(got, expectedDigest) {
		return fmt.Errorf(
			"subject[0] digest %q does not match expected artifact digest %q",
			got, expectedDigest,
		)
	}
	return nil
}

// Code is the verified content of a code-provenance bundle.
type Code struct {
	// Measurement is the attested launch measurement.
	Measurement *measurement.Measurement
	// Shape is the VM shape the artifact declares; nil when the predicate
	// carries no vm_shape field.
	Shape *policy.Shape
}

// VerifyCode verifies a code-provenance bundle against the repo's signing
// identity and the expected artifact digest, and returns the verified code
// measurement plus the VM shape the artifact declares.
func (c *Client) VerifyCode(bundleJSON []byte, repo, hexDigest string) (*Code, error) {
	result, err := c.VerifyBundle(bundleJSON, repo, hexDigest)
	if err != nil {
		return nil, fmt.Errorf("verifying bundle: %w", err)
	}
	m, err := measurementFromStatement(result.Statement)
	if err != nil {
		return nil, err
	}
	shape, err := shapeFromPredicate(result.Statement.Predicate.GetFields())
	if err != nil {
		return nil, err
	}
	return &Code{Measurement: m, Shape: shape}, nil
}

// shapeFromPredicate parses the optional vm_shape predicate member.
func shapeFromPredicate(fields map[string]*structpb.Value) (*policy.Shape, error) {
	v, ok := fields["vm_shape"]
	if !ok {
		return nil, nil
	}
	s := v.GetStructValue()
	if s == nil {
		return nil, fmt.Errorf("vm_shape is not an object")
	}
	shape := &policy.Shape{GPUs: new(int)}
	for name, dst := range map[string]*int{
		"cpus":      &shape.CPUs,
		"memory_mb": &shape.MemoryMB,
		"gpus":      shape.GPUs,
		"disks":     &shape.Disks,
	} {
		f, ok := s.GetFields()[name]
		if !ok {
			return nil, fmt.Errorf("vm_shape is missing %q", name)
		}
		*dst = int(f.GetNumberValue())
	}
	return shape, nil
}

func measurementFromStatement(statement *in_toto.Statement) (*measurement.Measurement, error) {
	predicateFields := statement.Predicate.GetFields()

	measurementType := measurement.PredicateType(statement.PredicateType)
	switch measurementType {
	case measurement.SnpTdxMultiPlatformV1:
		tdxMeasurementField, ok := predicateFields["tdx_measurement"]
		if !ok {
			return nil, fmt.Errorf("invalid multiplatform measurement: no tdx measurement")
		}
		if tdxMeasurementField == nil {
			return nil, fmt.Errorf("invalid multiplatform measurement: tdx measurement is nil")
		}
		tdxMeasurement := tdxMeasurementField.GetStructValue()
		if tdxMeasurement == nil {
			return nil, fmt.Errorf("invalid multiplatform measurement: tdx measurement is not a struct")
		}
		rtmrs := tdxMeasurement.GetFields()

		snpMeasurement, ok := predicateFields["snp_measurement"]
		if !ok {
			return nil, fmt.Errorf("invalid multiplatform measurement: no snp measurement")
		}
		if snpMeasurement == nil {
			return nil, fmt.Errorf("invalid multiplatform measurement: snp measurement is nil")
		}

		for _, rtmr := range []string{"rtmr1", "rtmr2"} {
			v, ok := rtmrs[rtmr]
			if !ok {
				return nil, fmt.Errorf("invalid multiplatform measurement: no %s", rtmr)
			}
			if v == nil {
				return nil, fmt.Errorf("invalid multiplatform measurement: %s is nil", rtmr)
			}
		}

		return &measurement.Measurement{
			Type: measurementType,
			Registers: []string{
				predicateFields["snp_measurement"].GetStringValue(),
				rtmrs["rtmr1"].GetStringValue(),
				rtmrs["rtmr2"].GetStringValue(),
			},
		}, nil
	default:
		return nil, fmt.Errorf("unsupported predicate type: %s", statement.PredicateType)
	}
}

// VerifyPlatformEndorsements verifies a Sigstore bundle for the
// platform-endorsements artifact against the publisher identity and returns
// the parsed, validated artifact.
func (c *Client) VerifyPlatformEndorsements(bundleJSON []byte, hexDigest string) (*policy.Artifact, error) {
	result, err := c.verifyBundleWithIdentity(bundleJSON, platformEndorsementsIdentity, hexDigest)
	if err != nil {
		return nil, fmt.Errorf("verifying platform endorsements bundle: %w", err)
	}

	if result.Statement.PredicateType != policy.ArtifactFormat {
		return nil, fmt.Errorf("unexpected predicate type: %s", result.Statement.PredicateType)
	}

	predicateJSON, err := protojson.Marshal(result.Statement.Predicate)
	if err != nil {
		return nil, fmt.Errorf("encoding platform endorsements predicate: %w", err)
	}
	return policy.Parse(predicateJSON)
}
