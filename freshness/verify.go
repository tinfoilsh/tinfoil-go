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
	DefaultMaxAge     = approval.DefaultMaxAge
	DefaultFutureSkew = approval.DefaultFutureSkew
)

type Policy struct {
	Artifact   Artifact
	Now        time.Time
	MaxAge     time.Duration
	FutureSkew time.Duration
}

func (p Policy) timePolicy() (approval.TimePolicy, error) {
	if err := p.Artifact.Validate(); err != nil {
		return approval.TimePolicy{}, err
	}
	return approval.NewTimePolicy(p.Now, p.MaxAge, p.FutureSkew, false)
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
	if v == nil || v.cryptographic == nil {
		return nil, fmt.Errorf("uninitialized freshness verifier")
	}
	timePolicy, err := policy.timePolicy()
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
	if s.artifact() != policy.Artifact {
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
	at, err := v.cryptographic.VerifyTimestamp(s.Predicate.Freshness.RFC3161Timestamp, input, timePolicy)
	if err != nil {
		return nil, fmt.Errorf("inner timestamp: %w", err)
	}
	return &Verified{Artifact: policy.Artifact, Reference: approval.EndorsementReference(payload), SigningKeyHint: hint, ApprovalTime: at}, nil
}

// VerifyTimestamp authenticates the prepared core's timestamp before signing.
func (v *Verifier) VerifyTimestamp(input, response []byte, policy Policy) (time.Time, error) {
	if v == nil || v.cryptographic == nil {
		return time.Time{}, fmt.Errorf("uninitialized freshness verifier")
	}
	timePolicy, err := policy.timePolicy()
	if err != nil {
		return time.Time{}, err
	}
	return v.cryptographic.VerifyTimestamp(response, input, timePolicy)
}
