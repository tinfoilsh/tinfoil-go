package provenance

import (
	"fmt"
	"regexp"
	"time"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/tinfoilsh/tinfoil-go/verifier/internal/strictjson"
)

const (
	FreshnessPredicateFormat = "https://tinfoil.sh/predicate/freshness-witness/v1"
	inTotoStatementV1        = "https://in-toto.io/Statement/v1"
	MaxFreshnessAge          = 7 * 24 * time.Hour
	MaxFreshnessFutureSkew   = 5 * time.Minute
)

var sha256DigestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type freshnessSubject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

type WitnessSubject struct {
	Name   string `json:"name"`
	Digest string `json:"digest"`
}

type WitnessEndorsement struct {
	Repo    string         `json:"repo"`
	Tag     string         `json:"tag"`
	Commit  string         `json:"commit"`
	Subject WitnessSubject `json:"subject"`
}

type FreshnessWitness struct {
	Format   string             `json:"format"`
	Endorses WitnessEndorsement `json:"endorses"`
}

type freshnessStatement struct {
	Type          string             `json:"_type"`
	Subject       []freshnessSubject `json:"subject"`
	PredicateType string             `json:"predicateType"`
	Predicate     FreshnessWitness   `json:"predicate"`
}

func AuthenticateFreshness(bundleJSON []byte, expected *AuthenticatedArtifact, now time.Time) (time.Time, error) {
	c, err := getDefaultClient()
	if err != nil {
		return time.Time{}, err
	}
	return c.AuthenticateFreshness(bundleJSON, expected, now)
}

func (c *Client) AuthenticateFreshness(bundleJSON []byte, expected *AuthenticatedArtifact, now time.Time) (time.Time, error) {
	if err := validateAuthenticatedArtifact(expected); err != nil {
		return time.Time{}, err
	}
	identity, err := freshnessIdentityForBundle(bundleJSON)
	if err != nil {
		return time.Time{}, err
	}
	result, err := c.verifyBundleWithIdentity(bundleJSON, identity, expected.Digest)
	if err != nil {
		return time.Time{}, fmt.Errorf("verifying freshness witness bundle: %w", err)
	}
	statement, err := parseFreshnessStatement(bundleJSON)
	if err != nil {
		return time.Time{}, err
	}
	if statement.Type != inTotoStatementV1 {
		return time.Time{}, fmt.Errorf("unexpected freshness statement type %q", statement.Type)
	}
	if statement.PredicateType != FreshnessPredicateFormat || statement.Predicate.Format != FreshnessPredicateFormat {
		return time.Time{}, fmt.Errorf("unexpected freshness predicate format")
	}
	if len(statement.Subject) != 1 || statement.Subject[0].Name != expected.SubjectName || statement.Subject[0].Digest["sha256"] != expected.Digest {
		return time.Time{}, fmt.Errorf("freshness statement subject does not match authenticated artifact")
	}
	if err := validateWitness(statement.Predicate, expected); err != nil {
		return time.Time{}, err
	}
	return validateFreshnessTime(result.VerifiedTimestamps, now)
}

func validateAuthenticatedArtifact(expected *AuthenticatedArtifact) error {
	if expected == nil {
		return fmt.Errorf("authenticated artifact is nil")
	}
	if !repoNameRE.MatchString(expected.Repo) {
		return fmt.Errorf("authenticated artifact repository is invalid")
	}
	if expected.Tag == "" {
		return fmt.Errorf("authenticated artifact tag is empty")
	}
	if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(expected.Commit) {
		return fmt.Errorf("authenticated artifact commit is malformed")
	}
	if expected.SubjectName == "" {
		return fmt.Errorf("authenticated artifact subject name is empty")
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(expected.Digest) {
		return fmt.Errorf("authenticated artifact digest is malformed")
	}
	return nil
}

func freshnessIdentityForBundle(bundleJSON []byte) (string, error) {
	var parsed bundle.Bundle
	if err := parsed.UnmarshalJSON(bundleJSON); err != nil {
		return "", fmt.Errorf("parsing freshness bundle: %w", err)
	}
	material := parsed.GetVerificationMaterial()
	if material == nil {
		return "", fmt.Errorf("freshness bundle has no verification material")
	}
	if len(material.GetTlogEntries()) > 0 {
		return publicFreshnessIdentity, nil
	}
	if len(material.GetTimestampVerificationData().GetRfc3161Timestamps()) > 0 {
		return privateFreshnessIdentity, nil
	}
	return "", fmt.Errorf("freshness bundle has no authenticated timestamp")
}

func validateFreshnessTime(timestamps []verify.TimestampVerificationResult, now time.Time) (time.Time, error) {
	var authenticatedAt time.Time
	for _, timestamp := range timestamps {
		if (timestamp.Type == "Tlog" || timestamp.Type == "TimestampAuthority") &&
			(authenticatedAt.IsZero() || timestamp.Timestamp.Before(authenticatedAt)) {
			authenticatedAt = timestamp.Timestamp
		}
	}
	if authenticatedAt.IsZero() {
		return time.Time{}, fmt.Errorf("freshness witness has no verified authenticated timestamp")
	}
	if authenticatedAt.After(now.Add(MaxFreshnessFutureSkew)) {
		return time.Time{}, fmt.Errorf("freshness witness timestamp is in the future")
	}
	if now.Sub(authenticatedAt) > MaxFreshnessAge {
		return time.Time{}, fmt.Errorf("freshness witness is stale")
	}
	return authenticatedAt, nil
}

func parseFreshnessStatement(bundleJSON []byte) (*freshnessStatement, error) {
	var parsed bundle.Bundle
	if err := parsed.UnmarshalJSON(bundleJSON); err != nil {
		return nil, fmt.Errorf("parsing freshness bundle: %w", err)
	}
	envelope := parsed.GetDsseEnvelope()
	if envelope == nil {
		return nil, fmt.Errorf("freshness bundle has no DSSE envelope")
	}
	var statement freshnessStatement
	if err := strictjson.Unmarshal(envelope.Payload, &statement); err != nil {
		return nil, fmt.Errorf("parsing freshness statement: %w", err)
	}
	return &statement, nil
}

func validateWitness(witness FreshnessWitness, expected *AuthenticatedArtifact) error {
	if witness.Endorses.Repo != expected.Repo || witness.Endorses.Tag != expected.Tag || witness.Endorses.Commit != expected.Commit || witness.Endorses.Subject.Name != expected.SubjectName || witness.Endorses.Subject.Digest != "sha256:"+expected.Digest {
		return fmt.Errorf("freshness witness does not match authenticated artifact")
	}
	if !sha256DigestRE.MatchString(witness.Endorses.Subject.Digest) {
		return fmt.Errorf("freshness witness subject digest is malformed")
	}
	return nil
}
