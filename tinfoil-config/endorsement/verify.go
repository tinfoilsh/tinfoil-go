package endorsement

import (
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/tinfoilsh/tinfoil-go/internal/approval"
)

const (
	DefaultMaxAge           = approval.DefaultMaxAge
	DefaultFutureSkew       = approval.DefaultFutureSkew
	SigstoreTimestampPolicy = approval.SigstoreTimestampPolicy
)

// SigningKey is application-provisioned trust, never material from collateral.
// A key remains authorized for its scope until removed from the trusted set.
type SigningKey struct {
	PublicKey  crypto.PublicKey
	AuditScope string
}

// Policy pins the identity and supplies the client's clock and freshness rules.
// Zero MaxAge and FutureSkew select the defaults. IgnoreFreshness skips the
// approval age check for archived material; Now is then optional and every
// other check still applies. Verified.ApprovalTime reports the authenticated time.
type Policy struct {
	Identity        string
	AuditScope      string
	Revision        string
	Digest          string
	Now             time.Time
	MaxAge          time.Duration
	FutureSkew      time.Duration
	IgnoreFreshness bool
}

type Verified struct {
	Name           string
	AuditScope     string
	Digest         string
	Reference      string
	SigningKeyHint string
	ApprovalTime   time.Time
}

type Verifier struct {
	cryptographic *approval.Verifier
	scopes        map[string]string
}

// NewVerifier builds an offline verifier. The supplied roots authenticate TSA
// and Rekor evidence; only keys in signingKeys can authorize a config approval.
func NewVerifier(trust root.TrustedMaterial, signingKeys []SigningKey) (*Verifier, error) {
	keys := make([]crypto.PublicKey, 0, len(signingKeys))
	scopes := make(map[string]string, len(signingKeys))
	for _, key := range signingKeys {
		if err := ValidateAuditScope(key.AuditScope); err != nil {
			return nil, err
		}
		hint, err := KeyHint(key.PublicKey)
		if err != nil {
			return nil, err
		}
		scopes[hint] = key.AuditScope
		keys = append(keys, key.PublicKey)
	}
	cryptographic, err := approval.NewVerifier(trust, keys)
	if err != nil {
		return nil, err
	}
	return &Verifier{cryptographic: cryptographic, scopes: scopes}, nil
}

// ValidatePins checks config expectations independently of clock and freshness settings.
func (p Policy) ValidatePins() error {
	if err := ValidateIdentity(p.Identity); err != nil {
		return err
	}
	if err := ValidateAuditScope(p.AuditScope); err != nil {
		return err
	}
	if p.Revision != "" {
		if _, _, err := ParseName(p.Identity + "/" + p.Revision); err != nil {
			return err
		}
	}
	if p.Digest != "" && !digestPattern.MatchString(p.Digest) {
		return fmt.Errorf("digest pin must be lowercase SHA-256")
	}
	return nil
}

func (p Policy) timePolicy() (approval.TimePolicy, error) {
	if err := p.ValidatePins(); err != nil {
		return approval.TimePolicy{}, err
	}
	return approval.NewTimePolicy(p.Now, p.MaxAge, p.FutureSkew, p.IgnoreFreshness)
}

// Verify authenticates exact config bytes, approval identity, signing authority,
// an independent approval timestamp, and Rekor v2 inclusion. It never accesses a network.
func (v *Verifier) Verify(config, bundleJSON []byte, policy Policy) (*Verified, error) {
	return v.verify(config, bundleJSON, policy, true)
}

// VerifyPrepared checks an approval without requiring log receipts.
// It authenticates the signed statement and timestamp but not transparency.
// Only Verify can authenticate a published approval.
func (v *Verifier) VerifyPrepared(config, bundleJSON []byte, policy Policy) error {
	_, err := v.verify(config, bundleJSON, policy, false)
	return err
}

func (v *Verifier) verify(config, bundleJSON []byte, policy Policy, requirePublication bool) (*Verified, error) {
	timePolicy, err := policy.timePolicy()
	if err != nil {
		return nil, err
	}
	if len(config) == 0 || len(config) > MaxConfigSize {
		return nil, fmt.Errorf("config size is outside allowed bounds")
	}
	b, err := approval.ParseBundle(bundleJSON, requirePublication)
	if err != nil {
		return nil, err
	}
	hint := b.GetVerificationMaterial().GetPublicKey().GetHint()
	if v.scopes[hint] != policy.AuditScope {
		return nil, fmt.Errorf("signer is not authorized for the expected audit scope")
	}
	payload := b.GetDsseEnvelope().GetPayload()
	s, err := ParseStatement(payload)
	if err != nil {
		return nil, err
	}
	identity, revision, err := ParseName(s.Subject[0].Name)
	if err != nil {
		return nil, err
	}
	if s.Predicate.AuditScope != policy.AuditScope || identity != policy.Identity || (policy.Revision != "" && revision != policy.Revision) {
		return nil, fmt.Errorf("config endorsement does not match the pinned identity, scope, or revision")
	}
	digest := sha256.Sum256(config)
	hexDigest := hex.EncodeToString(digest[:])
	if s.Subject[0].Digest["sha256"] != hexDigest || (policy.Digest != "" && policy.Digest != hexDigest) {
		return nil, fmt.Errorf("config bytes do not match the endorsed or pinned digest")
	}
	if _, err := v.cryptographic.Verify(b, digest[:], requirePublication); err != nil {
		return nil, err
	}
	input, err := s.TimestampInput()
	if err != nil {
		return nil, err
	}
	inner, err := v.cryptographic.VerifyTimestamp(s.Predicate.Freshness.RFC3161Timestamp, input, timePolicy)
	if err != nil {
		return nil, fmt.Errorf("inner timestamp: %w", err)
	}
	return &Verified{
		Name: s.Subject[0].Name, AuditScope: policy.AuditScope, Digest: hexDigest,
		Reference: approval.EndorsementReference(payload), SigningKeyHint: hint, ApprovalTime: inner,
	}, nil
}

// VerifyTimestamp authenticates a core's TSA response and checks its freshness.
// This does not authenticate a config endorsement or bind the response to a
// particular signing key.
func (v *Verifier) VerifyTimestamp(input, response []byte, policy Policy) (time.Time, error) {
	timePolicy, err := policy.timePolicy()
	if err != nil {
		return time.Time{}, err
	}
	return v.cryptographic.VerifyTimestamp(response, input, timePolicy)
}
