package sigstore

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/tinfoilsh/tinfoil-go/verifier/attestation"
	"github.com/tinfoilsh/tinfoil-go/verifier/github"
	"github.com/tinfoilsh/tinfoil-go/verifier/policy"
)

const (
	oidcIssuer = "https://token.actions.githubusercontent.com"

	// platformEndorsementsRepo publishes the platform-endorsements artifact.
	platformEndorsementsRepo = "tinfoilsh/platform-endorsements"
)

// platformEndorsementsIdentity is the only signing certificate identity
// accepted for the platform-endorsements artifact.
var platformEndorsementsIdentity = githubActionsIdentity(
	platformEndorsementsRepo,
	"build\\.yml",
	"refs/tags/v[0-9][^@]*",
)

type Client struct {
	trustRoot *root.TrustedRoot
}

func NewClient() (*Client, error) {
	trustRootJSON, err := FetchTrustRoot()
	if err != nil {
		return nil, fmt.Errorf("fetching trust root: %w", err)
	}

	trustRoot, err := root.NewTrustedRootFromJSON(trustRootJSON)
	if err != nil {
		return nil, fmt.Errorf("parsing trust root: %w", err)
	}

	return &Client{
		trustRoot: trustRoot,
	}, nil
}

func NewClientFromJSON(trustRootJSON []byte) (*Client, error) {
	trustRoot, err := root.NewTrustedRootFromJSON(trustRootJSON)
	if err != nil {
		return nil, fmt.Errorf("parsing trust root: %w", err)
	}
	return &Client{trustRoot: trustRoot}, nil
}

// FetchTrustRoot fetches the trust root from the Sigstore TUF repo
func FetchTrustRoot() ([]byte, error) {
	tufOpts := tuf.
		DefaultOptions().
		WithDisableLocalCache()
	//WithFetcher(util.NewFetcher())
	client, err := tuf.New(tufOpts)
	if err != nil {
		return nil, err
	}

	return client.GetTarget("trusted_root.json")
}

func (c *Client) VerifyBundle(bundleJSON []byte, repo, hexDigest string) (*verify.VerificationResult, error) {
	// TODO: Can we pin this to latest without fetching the latest release?
	sanRegex := githubActionsIdentity(repo, "[^@]+", "refs/tags/.+")
	return c.verifyBundleWithIdentity(bundleJSON, sanRegex, hexDigest)
}

func releaseIdentity(repo, tag string) string {
	return githubActionsIdentity(repo, "[^@]+", "refs/tags/"+regexp.QuoteMeta(tag))
}

func githubActionsIdentity(repo, workflowPattern, refPattern string) string {
	return "^https://github\\.com/" + regexp.QuoteMeta(repo) +
		"/\\.github/workflows/" + workflowPattern + "@" + refPattern + "$"
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

	certID, err := verify.NewShortCertificateIdentity(
		oidcIssuer,
		"",
		"",
		sanRegex,
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

func (c *Client) VerifyAttestation(
	bundleJSON []byte,
	repo, hexDigest string,
) (*attestation.Measurement, error) {
	result, err := c.VerifyBundle(bundleJSON, repo, hexDigest)
	return measurementFromResult(result, err)
}

// VerifyAttestationForRelease verifies an attestation signed for an exact release tag.
func (c *Client) VerifyAttestationForRelease(
	bundleJSON []byte,
	repo, tag, hexDigest string,
) (*attestation.Measurement, error) {
	result, err := c.verifyBundleWithIdentity(bundleJSON, releaseIdentity(repo, tag), hexDigest)
	return measurementFromResult(result, err)
}

func measurementFromResult(result *verify.VerificationResult, err error) (*attestation.Measurement, error) {
	if err != nil {
		return nil, fmt.Errorf("verifying bundle: %w", err)
	}

	predicate := result.Statement.Predicate
	predicateFields := predicate.Fields

	measurementType := attestation.PredicateType(result.Statement.PredicateType)
	switch measurementType {
	case attestation.SnpTdxMultiPlatformV1:
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

		// Validate multiplatform measurement format
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

		return &attestation.Measurement{
			Type: measurementType,
			Registers: []string{
				predicateFields["snp_measurement"].GetStringValue(),
				rtmrs["rtmr1"].GetStringValue(),
				rtmrs["rtmr2"].GetStringValue(),
			},
		}, nil
	default:
		return nil, fmt.Errorf("unsupported predicate type: %s", result.Statement.PredicateType)
	}
}

// FetchHardwareMeasurements fetches the MRTD and RTMR0 from a given hardware repo
func (c *Client) FetchHardwareMeasurements(repo, digest string) ([]*attestation.HardwareMeasurement, error) {
	sigstoreBundle, err := github.FetchAttestationBundle(repo, digest)
	if err != nil {
		return nil, err
	}

	bundle, err := c.VerifyBundle(sigstoreBundle, repo, digest)
	if err != nil {
		return nil, err
	}

	predicate := bundle.Statement.Predicate
	predicateType := bundle.Statement.PredicateType

	if attestation.PredicateType(predicateType) != attestation.HardwareMeasurementsV1 {
		return nil, fmt.Errorf("unexpected predicate type: %s", predicateType)
	}

	var measurements []*attestation.HardwareMeasurement
	for k, v := range predicate.Fields {
		structValue := v.GetStructValue()
		if structValue == nil {
			return nil, fmt.Errorf("invalid hardware measurement")
		}

		fields := structValue.Fields

		for _, field := range []string{"mrtd", "rtmr0"} {
			v, ok := fields[field]
			if !ok {
				return nil, fmt.Errorf("invalid hardware measurement: no %s", field)
			}
			if v == nil {
				return nil, fmt.Errorf("invalid hardware measurement: %s is nil", field)
			}
		}

		measurements = append(measurements, &attestation.HardwareMeasurement{
			ID:    fmt.Sprintf("%s@%s", k, digest),
			MRTD:  fields["mrtd"].GetStringValue(),
			RTMR0: fields["rtmr0"].GetStringValue(),
		})
	}
	return measurements, nil
}

// VerifyAttestation verifies the attested measurements of an enclave image
// against a trusted root (Sigstore) and returns the measurement payload contained in the DSSE.
// Deprecated: Use client.VerifyAttestation instead.
func VerifyAttestation(
	trustRootJSON, bundleJSON []byte,
	repo, hexDigest string,
) (*attestation.Measurement, error) {
	trustRoot, err := root.NewTrustedRootFromJSON(trustRootJSON)
	if err != nil {
		return nil, fmt.Errorf("parsing trust root: %w", err)
	}
	client := &Client{trustRoot: trustRoot}
	return client.VerifyAttestation(bundleJSON, repo, hexDigest)
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
	return policy.ParseArtifact(predicateJSON)
}

// LatestPlatformEndorsements fetches and verifies the latest
// platform-endorsements artifact (endorsed machine identities and their
// appraisal policies) from GitHub+Sigstore.
func (c *Client) LatestPlatformEndorsements() (*policy.Artifact, error) {
	digest, err := github.FetchLatestDigest(platformEndorsementsRepo)
	if err != nil {
		return nil, fmt.Errorf("fetching platform endorsements digest: %w", err)
	}
	bundleJSON, err := github.FetchAttestationBundle(platformEndorsementsRepo, digest)
	if err != nil {
		return nil, fmt.Errorf("fetching platform endorsements bundle: %w", err)
	}
	return c.VerifyPlatformEndorsements(bundleJSON, digest)
}

// LatestHardwareMeasurements fetches the latest hardware measurements from GitHub+Sigstore
func (c *Client) LatestHardwareMeasurements() ([]*attestation.HardwareMeasurement, error) {
	const repo = "tinfoilsh/hardware-measurements"
	digest, err := github.FetchLatestDigest(repo)
	if err != nil {
		return nil, err
	}

	return c.FetchHardwareMeasurements(repo, digest)
}
