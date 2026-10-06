package endorsement

import (
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
	configendorsement "github.com/tinfoilsh/tinfoil-go/endorsement/config"
	"github.com/tinfoilsh/tinfoil-go/internal/statement"
)

// ConfigSigningKey is application-provisioned trust, never material from collateral.
// A key remains authorized for its scope until removed from the trusted set.
type ConfigSigningKey struct {
	PublicKey  crypto.PublicKey
	AuditScope string
}

// ConfigPolicy pins the identity and supplies the client's clock and freshness rules.
// Zero MaxAge and FutureSkew select the defaults. IgnoreFreshness skips the
// approval age check for archived material; Now is then optional and every
// other check still applies. ConfigVerified.ApprovalTime reports the authenticated time.
type ConfigPolicy struct {
	Identity        string
	AuditScope      string
	Revision        string
	Digest          string
	Now             time.Time
	MaxAge          time.Duration
	FutureSkew      time.Duration
	IgnoreFreshness bool
}

type ConfigVerified struct {
	Name           string
	AuditScope     string
	Digest         string
	Reference      string
	SigningKeyHint string
	ApprovalTime   time.Time
}

type ConfigVerifier struct {
	cryptographic *endorsementVerifier
	scopes        map[string]string
}

// NewConfigVerifier builds an offline verifier. The supplied roots authenticate TSA
// and Rekor evidence; only keys in signingKeys can authorize a config approval.
func NewConfigVerifier(trust root.TrustedMaterial, signingKeys []ConfigSigningKey) (*ConfigVerifier, error) {
	keys := make([]crypto.PublicKey, 0, len(signingKeys))
	scopes := make(map[string]string, len(signingKeys))
	for _, key := range signingKeys {
		if err := configendorsement.ValidateAuditScope(key.AuditScope); err != nil {
			return nil, err
		}
		hint, err := statement.KeyHint(key.PublicKey)
		if err != nil {
			return nil, err
		}
		scopes[hint] = key.AuditScope
		keys = append(keys, key.PublicKey)
	}
	cryptographic, err := newEndorsementVerifier(trust, keys)
	if err != nil {
		return nil, err
	}
	return &ConfigVerifier{cryptographic: cryptographic, scopes: scopes}, nil
}

// ValidatePins checks config expectations independently of clock and freshness settings.
func (p ConfigPolicy) ValidatePins() error {
	if err := configendorsement.ValidateIdentity(p.Identity); err != nil {
		return err
	}
	if err := configendorsement.ValidateAuditScope(p.AuditScope); err != nil {
		return err
	}
	if p.Revision != "" {
		if _, _, err := configendorsement.ParseName(p.Identity + "/" + p.Revision); err != nil {
			return err
		}
	}
	if p.Digest != "" && !sha256DigestRE.MatchString(p.Digest) {
		return fmt.Errorf("digest pin must be lowercase SHA-256")
	}
	return nil
}

func (p ConfigPolicy) timePolicy() (timePolicy, error) {
	if err := p.ValidatePins(); err != nil {
		return timePolicy{}, err
	}
	return newTimePolicy(p.Now, p.MaxAge, p.FutureSkew, p.IgnoreFreshness)
}

// Verify authenticates exact config bytes, approval identity, signing authority,
// an independent approval timestamp, and Rekor v2 inclusion. It never accesses a network.
func (v *ConfigVerifier) Verify(config, bundleJSON []byte, policy ConfigPolicy) (*ConfigVerified, error) {
	timePolicy, err := policy.timePolicy()
	if err != nil {
		return nil, err
	}
	if len(config) == 0 || len(config) > configendorsement.MaxConfigSize {
		return nil, fmt.Errorf("config size is outside allowed bounds")
	}
	b, err := parseEndorsementBundle(bundleJSON)
	if err != nil {
		return nil, err
	}
	hint := b.GetVerificationMaterial().GetPublicKey().GetHint()
	if v.scopes[hint] != policy.AuditScope {
		return nil, fmt.Errorf("signer is not authorized for the expected audit scope")
	}
	payload := b.GetDsseEnvelope().GetPayload()
	s, err := configendorsement.ParseStatement(payload)
	if err != nil {
		return nil, err
	}
	identity, revision, err := configendorsement.ParseName(s.Subject[0].Name)
	if err != nil {
		return nil, err
	}
	if s.Predicate.AuditScope != policy.AuditScope || identity != policy.Identity || (policy.Revision != "" && revision != policy.Revision) {
		return nil, fmt.Errorf("config endorsement does not match the pinned identity, scope, or revision")
	}
	digest := sha256.Sum256(config)
	hexDigest := hex.EncodeToString(digest[:])
	if s.Subject[0].Digest[statement.DigestAlgorithm] != hexDigest || (policy.Digest != "" && policy.Digest != hexDigest) {
		return nil, fmt.Errorf("config bytes do not match the endorsed or pinned digest")
	}
	if _, err := v.cryptographic.Verify(b, digest[:]); err != nil {
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
	return &ConfigVerified{
		Name: s.Subject[0].Name, AuditScope: policy.AuditScope, Digest: hexDigest,
		Reference: statement.EndorsementReference(payload), SigningKeyHint: hint, ApprovalTime: inner,
	}, nil
}

func (c *Client) ConfigVerifier(keys []ConfigSigningKey) (*ConfigVerifier, error) {
	return NewConfigVerifier(c.trustRoot, keys)
}
