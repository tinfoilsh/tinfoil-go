// Package freshness authenticates Tinfoil approvals of platform and runtime releases.
package freshness

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"

	"github.com/digitorus/timestamp"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/tinfoilsh/tinfoil-go/internal/approval"
	"github.com/tinfoilsh/tinfoil-go/internal/canonical"
	"golang.org/x/mod/semver"
)

const (
	StatementType   = "https://in-toto.io/Statement/v1"
	PredicateType   = "https://tinfoil.sh/predicate/artifact-freshness/v1"
	PayloadType     = approval.PayloadType
	BundleType      = approval.BundleType
	KindPlatform    = "platform"
	KindRuntime     = "runtime"
	PlatformRepo    = "tinfoilsh/platform-endorsements"
	RuntimeRepo     = "tinfoilsh/cvmimage"
	PlatformName    = "platform-endorsements-igvm.json"
	freshnessDomain = "tinfoil-artifact-freshness/v1\x00"
)

// Artifact identifies exact release bytes, independently authenticated by the caller.
type Artifact struct {
	Kind   string `json:"kind"`
	Repo   string `json:"repo"`
	Tag    string `json:"tag"`
	Name   string `json:"name"`
	Digest string `json:"digest"`
}

func (a Artifact) Validate() error {
	if !semver.IsValid(a.Tag) || semver.Canonical(a.Tag) != a.Tag {
		return fmt.Errorf("artifact tag must be a canonical semantic version")
	}
	switch a.Kind {
	case KindPlatform:
		if a.Repo != PlatformRepo || a.Name != PlatformName {
			return fmt.Errorf("platform freshness requires the IGVM platform artifact")
		}
	case KindRuntime:
		if a.Repo != RuntimeRepo || a.Name != RuntimeName(a.Tag) {
			return fmt.Errorf("runtime freshness requires the versioned runtime manifest")
		}
	default:
		return fmt.Errorf("unsupported freshness artifact kind %q", a.Kind)
	}
	_, err := canonical.DecodeLowerHex("artifact digest", a.Digest, sha256.Size)
	return err
}

func RuntimeName(tag string) string { return "tinfoil-inference-" + tag + "-manifest.json" }

type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

type Timestamp struct {
	RFC3161Timestamp []byte `json:"rfc3161Timestamp"`
}

type Predicate struct {
	Kind      string     `json:"kind"`
	Repo      string     `json:"repo"`
	Tag       string     `json:"tag"`
	Freshness *Timestamp `json:"freshness,omitempty"`
}

type Statement struct {
	Type          string    `json:"_type"`
	Subject       []Subject `json:"subject"`
	PredicateType string    `json:"predicateType"`
	Predicate     Predicate `json:"predicate"`
}

func NewStatement(artifact Artifact) (*Statement, error) {
	if err := artifact.Validate(); err != nil {
		return nil, err
	}
	return &Statement{
		Type: StatementType, PredicateType: PredicateType,
		Subject:   []Subject{{Name: artifact.Name, Digest: map[string]string{"sha256": artifact.Digest}}},
		Predicate: Predicate{Kind: artifact.Kind, Repo: artifact.Repo, Tag: artifact.Tag},
	}, nil
}

func (s *Statement) artifact() Artifact {
	return Artifact{Kind: s.Predicate.Kind, Repo: s.Predicate.Repo, Tag: s.Predicate.Tag, Name: s.Subject[0].Name, Digest: s.Subject[0].Digest["sha256"]}
}

func (s *Statement) validate(requireTimestamp bool) error {
	if s == nil || s.Type != StatementType || s.PredicateType != PredicateType || len(s.Subject) != 1 || len(s.Subject[0].Digest) != 1 {
		return fmt.Errorf("unsupported artifact freshness statement")
	}
	if err := s.artifact().Validate(); err != nil {
		return err
	}
	if requireTimestamp && (s.Predicate.Freshness == nil || len(s.Predicate.Freshness.RFC3161Timestamp) == 0) {
		return fmt.Errorf("artifact freshness requires an inner timestamp")
	}
	if s.Predicate.Freshness != nil && len(s.Predicate.Freshness.RFC3161Timestamp) > approval.MaxTimestampSize {
		return fmt.Errorf("inner timestamp exceeds size limit")
	}
	return nil
}

// TimestampInput returns the domain-separated canonical core, for a TSA client
// that hashes its input once with SHA-256.
func (s *Statement) TimestampInput() ([]byte, error) {
	if err := s.validate(false); err != nil {
		return nil, err
	}
	core := *s
	core.Predicate.Freshness = nil
	encoded, err := json.Marshal(core)
	if err != nil {
		return nil, err
	}
	canonical := jsontext.Value(encoded)
	if err := canonical.Canonicalize(); err != nil {
		return nil, err
	}
	return append([]byte(freshnessDomain), canonical...), nil
}

// Complete checks the timestamp imprint, not TSA trust. Publishers must call
// Verifier.VerifyTimestamp before signing and Verify after logging.
func (s *Statement) Complete(response []byte) ([]byte, error) {
	if len(response) == 0 || len(response) > approval.MaxTimestampSize {
		return nil, fmt.Errorf("timestamp response size is outside allowed bounds")
	}
	input, err := s.TimestampInput()
	if err != nil {
		return nil, err
	}
	imprint := sha256.Sum256(input)
	ts, err := timestamp.ParseResponse(response)
	if err != nil {
		return nil, err
	}
	if ts.HashAlgorithm != crypto.SHA256 || !bytes.Equal(ts.HashedMessage, imprint[:]) {
		return nil, fmt.Errorf("timestamp response does not match approval core")
	}
	complete := *s
	complete.Predicate.Freshness = &Timestamp{RFC3161Timestamp: bytes.Clone(response)}
	return json.Marshal(complete)
}

func ParseStatement(payload []byte) (*Statement, error) {
	if len(payload) == 0 || len(payload) > approval.MaxStatementSize {
		return nil, fmt.Errorf("statement size is outside allowed bounds")
	}
	var s Statement
	if err := json.Unmarshal(payload, &s, json.RejectUnknownMembers(true)); err != nil {
		return nil, err
	}
	if err := s.validate(true); err != nil {
		return nil, err
	}
	return &s, nil
}

func EndorsementReference(payload []byte) (string, error) {
	if _, err := ParseStatement(payload); err != nil {
		return "", err
	}
	digest := sha256.Sum256(dsse.PAE(PayloadType, payload))
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func KeyHint(key crypto.PublicKey) (string, error) { return approval.KeyHint(key) }
