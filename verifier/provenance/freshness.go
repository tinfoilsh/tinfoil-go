package provenance

import (
	"encoding/json/v2"
	"fmt"
	"regexp"
	"time"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

const (
	FreshnessPredicateFormat     = "https://tinfoil.sh/predicate/freshness-witness/v1"
	inTotoStatementV1            = "https://in-toto.io/Statement/v1"
	transparencyLogTimestampType = "Tlog"
	sha256DigestPrefix           = "sha256:"
	// MaxFreshnessAge is the default maximum witness age.
	MaxFreshnessAge        = 7 * 24 * time.Hour
	MaxFreshnessFutureSkew = 5 * time.Minute
)

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
	return AuthenticateFreshnessWithMaxAge(bundleJSON, expected, now, MaxFreshnessAge)
}

// AuthenticateFreshnessWithMaxAge authenticates a witness with a positive maximum age.
func AuthenticateFreshnessWithMaxAge(bundleJSON []byte, expected *AuthenticatedArtifact, now time.Time, maxAge time.Duration) (time.Time, error) {
	c, err := getDefaultClient()
	if err != nil {
		return time.Time{}, err
	}
	return c.AuthenticateFreshnessWithMaxAge(bundleJSON, expected, now, maxAge)
}

func (c *Client) AuthenticateFreshness(bundleJSON []byte, expected *AuthenticatedArtifact, now time.Time) (time.Time, error) {
	return c.AuthenticateFreshnessWithMaxAge(bundleJSON, expected, now, MaxFreshnessAge)
}

// AuthenticateFreshnessWithMaxAge uses maxAge for witness acceptance. The witness
// expires at the returned authenticated timestamp plus maxAge, exclusively.
func (c *Client) AuthenticateFreshnessWithMaxAge(bundleJSON []byte, expected *AuthenticatedArtifact, now time.Time, maxAge time.Duration) (time.Time, error) {
	if maxAge <= 0 {
		return time.Time{}, fmt.Errorf("freshness max age must be positive")
	}
	if err := validateAuthenticatedArtifact(expected); err != nil {
		return time.Time{}, err
	}
	result, err := c.verifyBundleWithIdentity(bundleJSON, freshnessWitnessIdentity, expected.Digest)
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
	return validateFreshnessTime(result.VerifiedTimestamps, now, maxAge)
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

func validateFreshnessTime(timestamps []verify.TimestampVerificationResult, now time.Time, maxAge time.Duration) (time.Time, error) {
	var loggedAt time.Time
	for _, timestamp := range timestamps {
		if timestamp.Type == transparencyLogTimestampType && (loggedAt.IsZero() || timestamp.Timestamp.Before(loggedAt)) {
			loggedAt = timestamp.Timestamp
		}
	}
	if loggedAt.IsZero() {
		return time.Time{}, fmt.Errorf("freshness witness has no verified transparency-log timestamp")
	}
	if loggedAt.After(now.Add(MaxFreshnessFutureSkew)) {
		return time.Time{}, fmt.Errorf("freshness witness timestamp is in the future")
	}
	// Match request admission: a witness is expired at its deadline, not just after it.
	if !now.Before(loggedAt.Add(maxAge)) {
		return time.Time{}, fmt.Errorf("freshness witness is stale")
	}
	return loggedAt, nil
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
	if err := json.Unmarshal(envelope.Payload, &statement, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("parsing freshness statement: %w", err)
	}
	return &statement, nil
}

// validateWitness binds the witness to an artifact checked by validateAuthenticatedArtifact.
func validateWitness(witness FreshnessWitness, expected *AuthenticatedArtifact) error {
	if witness.Endorses.Repo != expected.Repo || witness.Endorses.Tag != expected.Tag || witness.Endorses.Commit != expected.Commit || witness.Endorses.Subject.Name != expected.SubjectName || witness.Endorses.Subject.Digest != sha256DigestPrefix+expected.Digest {
		return fmt.Errorf("freshness witness does not match authenticated artifact")
	}
	return nil
}
