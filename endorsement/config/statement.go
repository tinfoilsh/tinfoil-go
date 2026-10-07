// Package config defines and constructs registry config endorsement statements.
package config

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"fmt"
	"regexp"
	"strings"

	"github.com/tinfoilsh/tinfoil-go/internal/statement"
)

const (
	StatementType    = statement.StatementType
	PredicateType    = "https://tinfoil.sh/predicate/config-endorsement/v1"
	PayloadType      = statement.PayloadType
	BundleType       = statement.BundleType
	MaxConfigSize    = 1 << 20
	MaxBundleSize    = statement.MaxBundleSize
	MaxStatementSize = statement.MaxStatementSize
	MaxTimestampSize = statement.MaxTimestampSize

	identityComponentCount = 2
	maxSlugLength          = 63
	maxRevisionLength      = 128
	freshnessDomain        = "tinfoil-config-freshness/v1\x00"
)

var (
	slugPattern     = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
	revisionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	digestPattern   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type Statement struct {
	Type          string    `json:"_type"`
	Subject       []Subject `json:"subject"`
	PredicateType string    `json:"predicateType"`
	Predicate     Predicate `json:"predicate"`
}

type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

type Predicate struct {
	Freshness *Freshness `json:"freshness,omitempty"`
}

type Freshness struct {
	RFC3161Timestamp []byte `json:"rfc3161Timestamp"`
}

// NewStatement prepares an unsigned approval of exact config bytes.
// Config schema validation and publication authorization belong to the caller.
func NewStatement(name string, config []byte) (*Statement, error) {
	if len(config) == 0 || len(config) > MaxConfigSize {
		return nil, fmt.Errorf("config size must be between 1 and %d bytes", MaxConfigSize)
	}
	digest := sha256.Sum256(config)
	s := &Statement{
		Type:          StatementType,
		Subject:       []Subject{{Name: name, Digest: map[string]string{statement.DigestAlgorithm: hex.EncodeToString(digest[:])}}},
		PredicateType: PredicateType,
	}
	if err := s.validate(false); err != nil {
		return nil, err
	}
	return s, nil
}

// ValidateIdentity accepts a canonical /org/project identity.
func ValidateIdentity(identity string) error {
	parts := strings.Split(identity, "/")
	if len(parts) != identityComponentCount+1 || parts[0] != "" {
		return fmt.Errorf("invalid config identity %q", identity)
	}
	for _, part := range parts[1:] {
		if len(part) > maxSlugLength || !slugPattern.MatchString(part) {
			return fmt.Errorf("invalid config identity component %q", part)
		}
	}
	return nil
}

// ParseName splits a canonical versioned config name into identity and revision.
func ParseName(name string) (identity, revision string, err error) {
	if strings.ContainsRune(name, '\x00') {
		return "", "", fmt.Errorf("invalid config name")
	}
	last := strings.LastIndexByte(name, '/')
	if last < 0 {
		return "", "", fmt.Errorf("config name has no revision")
	}
	identity, revision = name[:last], name[last+1:]
	if err := ValidateIdentity(identity); err != nil {
		return "", "", err
	}
	if len(revision) > maxRevisionLength || !revisionPattern.MatchString(revision) {
		return "", "", fmt.Errorf("invalid config revision %q", revision)
	}
	return identity, revision, nil
}

func (s *Statement) validate(requireTimestamp bool) error {
	if s == nil || s.Type != StatementType || s.PredicateType != PredicateType {
		return fmt.Errorf("unsupported config endorsement statement type")
	}
	if len(s.Subject) != 1 {
		return fmt.Errorf("config endorsement requires exactly one subject")
	}
	if _, _, err := ParseName(s.Subject[0].Name); err != nil {
		return err
	}
	if len(s.Subject[0].Digest) != 1 || !digestPattern.MatchString(s.Subject[0].Digest[statement.DigestAlgorithm]) {
		return fmt.Errorf("subject requires one lowercase SHA-256 digest")
	}
	if requireTimestamp && (s.Predicate.Freshness == nil || len(s.Predicate.Freshness.RFC3161Timestamp) == 0) {
		return fmt.Errorf("config endorsement requires an inner timestamp")
	}
	if s.Predicate.Freshness != nil && len(s.Predicate.Freshness.RFC3161Timestamp) > MaxTimestampSize {
		return fmt.Errorf("inner timestamp exceeds size limit")
	}
	return nil
}

// TimestampInput returns the domain-separated canonical core. RFC 3161 clients
// hash this input once; do not pass TimestampImprint to a client that hashes it.
func (s *Statement) TimestampInput() ([]byte, error) {
	if err := s.validate(false); err != nil {
		return nil, err
	}
	core := *s
	core.Predicate.Freshness = nil
	return statement.TimestampInput(freshnessDomain, core)
}

func (s *Statement) TimestampImprint() ([sha256.Size]byte, error) {
	input, err := s.TimestampInput()
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(input), nil
}

// Complete embeds a response over the prepared core. This checks its imprint,
// not TSA trust; the completed publication still requires verification.
func (s *Statement) Complete(response []byte) ([]byte, error) {
	input, err := s.TimestampInput()
	if err != nil {
		return nil, err
	}
	if _, err := statement.ParseTimestamp(response, input); err != nil {
		return nil, err
	}
	complete := *s
	complete.Predicate.Freshness = &Freshness{RFC3161Timestamp: bytes.Clone(response)}
	return json.Marshal(complete)
}

// ParseStatement strictly decodes the profile without authenticating it.
func ParseStatement(payload []byte) (*Statement, error) {
	if len(payload) == 0 || len(payload) > MaxStatementSize {
		return nil, fmt.Errorf("statement size is outside allowed bounds")
	}
	var s Statement
	if err := json.Unmarshal(payload, &s, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("decoding config endorsement: %w", err)
	}
	if err := s.validate(true); err != nil {
		return nil, err
	}
	return &s, nil
}

// EndorsementReference identifies the signed message independently of its
// signature encoding and replaceable verification evidence.
func EndorsementReference(payload []byte) (string, error) {
	if _, err := ParseStatement(payload); err != nil {
		return "", err
	}
	return statement.EndorsementReference(payload), nil
}

func KeyHint(publicKey crypto.PublicKey) (string, error) {
	return statement.KeyHint(publicKey)
}
