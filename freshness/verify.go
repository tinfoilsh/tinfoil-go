package freshness

import (
	"crypto"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/tinfoilsh/tinfoil-go/internal/approval"
)

const (
	DefaultMaxAge     = 7 * 24 * time.Hour
	DefaultFutureSkew = 5 * time.Minute
)

type Policy struct {
	Artifact   Artifact
	Now        time.Time
	MaxAge     time.Duration
	FutureSkew time.Duration
}

func (p Policy) normalized() (Policy, error) {
	if err := p.Artifact.Validate(); err != nil {
		return p, err
	}
	if p.Now.IsZero() || p.MaxAge < 0 || p.FutureSkew < 0 {
		return p, fmt.Errorf("clock and nonnegative age and skew are required")
	}
	if p.MaxAge == 0 {
		p.MaxAge = DefaultMaxAge
	}
	if p.FutureSkew == 0 {
		p.FutureSkew = DefaultFutureSkew
	}
	return p, nil
}

func (p Policy) verifyTime(at time.Time) error {
	if at.Before(p.Now.Add(-p.MaxAge)) {
		return fmt.Errorf("artifact approval is too old")
	}
	if at.After(p.Now.Add(p.FutureSkew)) {
		return fmt.Errorf("timestamp is in the future")
	}
	return nil
}

type Verified struct {
	Artifact
	Reference      string
	SigningKeyHint string
	ApprovalTime   time.Time
}

type Verifier struct{ cryptographic *approval.Verifier }

// NewVerifier pins Tinfoil's artifact approval keys, independently of any org's
// config signing authority. Verification never learns keys from collateral.
func NewVerifier(trust root.TrustedMaterial, keys []crypto.PublicKey) (*Verifier, error) {
	v, err := approval.NewVerifier(trust, keys)
	if err != nil {
		return nil, err
	}
	return &Verifier{cryptographic: v}, nil
}

// Verify authenticates the artifact binding, signature, inner TSA token, and
// Rekor v2 inclusion. The caller separately verifies the artifact's build provenance.
func (v *Verifier) Verify(bundleJSON []byte, policy Policy) (*Verified, error) {
	policy, err := policy.normalized()
	if err != nil {
		return nil, err
	}
	b, err := approval.ParseBundle(bundleJSON, true)
	if err != nil {
		return nil, err
	}
	payload := b.GetDsseEnvelope().GetPayload()
	s, err := ParseStatement(payload)
	if err != nil {
		return nil, err
	}
	if s.Artifact() != policy.Artifact {
		return nil, fmt.Errorf("freshness approval does not match the expected artifact")
	}
	digest, err := hex.DecodeString(policy.Artifact.Digest)
	if err != nil {
		return nil, err
	}
	hint, err := v.cryptographic.Verify(b, digest, true)
	if err != nil {
		return nil, err
	}
	input, err := s.TimestampInput()
	if err != nil {
		return nil, err
	}
	at, err := v.VerifyTimestamp(input, s.Predicate.Freshness.RFC3161Timestamp, policy)
	if err != nil {
		return nil, fmt.Errorf("inner timestamp: %w", err)
	}
	ref, err := EndorsementReference(payload)
	if err != nil {
		return nil, err
	}
	return &Verified{Artifact: policy.Artifact, Reference: ref, SigningKeyHint: hint, ApprovalTime: at}, nil
}

// VerifyTimestamp authenticates the prepared core's timestamp before signing.
func (v *Verifier) VerifyTimestamp(input, response []byte, policy Policy) (time.Time, error) {
	policy, err := policy.normalized()
	if err != nil {
		return time.Time{}, err
	}
	at, err := v.cryptographic.VerifyTimestamp(response, input)
	if err != nil {
		return time.Time{}, err
	}
	if err := policy.verifyTime(at); err != nil {
		return time.Time{}, err
	}
	return at, nil
}
