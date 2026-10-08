package endorsement

import (
	"crypto"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/tinfoilsh/tinfoil-go/endorsement/freshness"
	"github.com/tinfoilsh/tinfoil-go/internal/statement"
)

type FreshnessPolicy struct {
	Artifact        freshness.Artifact
	Now             time.Time
	MaxAge          time.Duration
	FutureSkew      time.Duration
	IgnoreFreshness bool
}

func (p FreshnessPolicy) timePolicy() (timePolicy, error) {
	if err := p.Artifact.Validate(); err != nil {
		return timePolicy{}, err
	}
	return newTimePolicy(p.Now, p.MaxAge, p.FutureSkew, p.IgnoreFreshness)
}

type FreshnessVerified struct {
	freshness.Artifact
	Reference      string
	SigningKeyHint string
	ApprovalTime   time.Time
}

type FreshnessVerifier struct{ cryptographic *endorsementVerifier }

// NewFreshnessVerifier pins Tinfoil's artifact approval keys, independently of any org's
// config signing authority. Verification never learns keys from collateral.
func NewFreshnessVerifier(trust root.TrustedMaterial, keys []crypto.PublicKey) (*FreshnessVerifier, error) {
	v, err := newEndorsementVerifier(trust, keys)
	if err != nil {
		return nil, err
	}
	return &FreshnessVerifier{cryptographic: v}, nil
}

// Verify authenticates the artifact binding, signature, inner TSA token, and
// Rekor v2 inclusion. The caller separately verifies the artifact's build provenance.
func (v *FreshnessVerifier) Verify(bundleJSON []byte, policy FreshnessPolicy) (*FreshnessVerified, error) {
	if v == nil || v.cryptographic == nil {
		return nil, fmt.Errorf("uninitialized freshness verifier")
	}
	timePolicy, err := policy.timePolicy()
	if err != nil {
		return nil, err
	}
	b, err := parseEndorsementBundle(bundleJSON)
	if err != nil {
		return nil, err
	}
	payload := b.GetDsseEnvelope().GetPayload()
	s, err := freshness.ParseStatement(payload)
	if err != nil {
		return nil, err
	}
	artifact := freshness.Artifact{Kind: s.Predicate.Kind, Repo: s.Predicate.Repo, Tag: s.Predicate.Tag, Name: s.Subject[0].Name, Digest: s.Subject[0].Digest[statement.DigestAlgorithm]}
	if artifact != policy.Artifact {
		return nil, fmt.Errorf("freshness approval does not match the expected artifact")
	}
	digest, err := hex.DecodeString(policy.Artifact.Digest)
	if err != nil {
		return nil, err
	}
	hint, err := v.cryptographic.Verify(b, digest)
	if err != nil {
		return nil, err
	}
	input, err := s.TimestampInput()
	if err != nil {
		return nil, err
	}
	at, err := v.cryptographic.VerifyTimestamp(s.Predicate.Freshness.RFC3161Timestamp, input, timePolicy)
	if err != nil {
		return nil, fmt.Errorf("inner timestamp: %w", err)
	}
	return &FreshnessVerified{Artifact: policy.Artifact, Reference: statement.EndorsementReference(payload), SigningKeyHint: hint, ApprovalTime: at}, nil
}

func (c *Client) FreshnessVerifier(keys []crypto.PublicKey) (*FreshnessVerifier, error) {
	return NewFreshnessVerifier(c.trustRoot, keys)
}
