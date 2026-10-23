package endorsement

import (
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
	configendorsement "github.com/tinfoilsh/tinfoil-go/endorsement/config"
	"github.com/tinfoilsh/tinfoil-go/endorsement/scope"
	"github.com/tinfoilsh/tinfoil-go/internal/statement"
	"github.com/tinfoilsh/tinfoil-go/verify/document/collateral"
)

// ConfigPolicy pins the identity and supplies the client's clock and freshness rules.
// Zero MaxAge and FutureSkew select the defaults; Now is required.
// ConfigVerified.ApprovalTime reports the authenticated time.
type ConfigPolicy struct {
	Identity   string
	Revision   string
	Digest     string
	Now        time.Time
	MaxAge     time.Duration
	FutureSkew time.Duration
	Scope      scope.Pins
}

type ConfigVerified struct {
	Name           string
	Digest         string
	Reference      string
	SigningKeyHint string
	ApprovalTime   time.Time
	Runtime        *configendorsement.RuntimeReference
	Scope          scope.Identity
	ScopeExpiresAt time.Time
}

type ConfigVerifier struct {
	cryptographic *endorsementVerifier
	scopes        *ScopeVerifier
}

// NewConfigVerifier builds an offline verifier. The supplied roots authenticate TSA
// and Rekor evidence; only keys in signingKeys can authorize a config approval.
func NewConfigVerifier(trust root.TrustedMaterial, keys []crypto.PublicKey) (*ConfigVerifier, error) {
	cryptographic, err := newEndorsementVerifier(trust, keys)
	if err != nil {
		return nil, err
	}
	return &ConfigVerifier{cryptographic: cryptographic}, nil
}

// ValidatePins checks config expectations independently of clock and freshness settings.
func (p ConfigPolicy) ValidatePins() error {
	if p.Identity != "" {
		if err := configendorsement.ValidateIdentity(p.Identity); err != nil {
			return err
		}
	}
	if p.Revision != "" {
		if err := configendorsement.ValidateRevision(p.Revision); err != nil {
			return err
		}
	}
	if p.Digest != "" && !sha256DigestRE.MatchString(p.Digest) {
		return fmt.Errorf("digest pin must be lowercase SHA-256")
	}
	return p.Scope.Validate()
}

func (p ConfigPolicy) timePolicy() (timePolicy, error) {
	if err := p.ValidatePins(); err != nil {
		return timePolicy{}, err
	}
	return newTimePolicy(p.Now, p.MaxAge, p.FutureSkew)
}

// Verify authenticates exact config bytes, approval identity, signing authority,
// an independent approval timestamp, and Rekor v2 inclusion. It never accesses a network.
func (v *ConfigVerifier) Verify(config, bundleJSON []byte, policy ConfigPolicy) (*ConfigVerified, error) {
	if len(config) == 0 || len(config) > configendorsement.MaxConfigSize {
		return nil, fmt.Errorf("config size is outside allowed bounds")
	}
	return v.verify(config, bundleJSON, nil, policy)
}

func (v *ConfigVerifier) VerifyDigest(bundleJSON []byte, policy ConfigPolicy) (*ConfigVerified, error) {
	return v.verify(nil, bundleJSON, nil, policy)
}

func (v *ConfigVerifier) VerifyScoped(bundleJSON []byte, certificate collateral.ScopeCertificate, policy ConfigPolicy) (*ConfigVerified, error) {
	if v.scopes == nil {
		return nil, fmt.Errorf("registry scope trust is not configured")
	}
	return v.verify(nil, bundleJSON, &certificate, policy)
}

func (v *ConfigVerifier) verify(config, bundleJSON []byte, certificate *collateral.ScopeCertificate, policy ConfigPolicy) (*ConfigVerified, error) {
	timePolicy, err := policy.timePolicy()
	if err != nil {
		return nil, err
	}
	b, err := parseEndorsementBundle(bundleJSON)
	if err != nil {
		return nil, err
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
	if (policy.Identity != "" && identity != policy.Identity) || (policy.Revision != "" && revision != policy.Revision) {
		return nil, fmt.Errorf("config endorsement does not match the pinned identity or revision")
	}
	hexDigest := s.Subject[0].Digest[statement.DigestAlgorithm]
	if policy.Digest != "" && policy.Digest != hexDigest {
		return nil, fmt.Errorf("config endorsement does not match the pinned digest")
	}
	if config == nil {
		if s.PredicateType != configendorsement.PredicateTypeV2 {
			return nil, fmt.Errorf("digest verification requires a v2 config endorsement")
		}
	} else {
		digest := sha256.Sum256(config)
		if hex.EncodeToString(digest[:]) != hexDigest {
			return nil, fmt.Errorf("config bytes do not match the endorsed digest")
		}
		if s.Predicate.Runtime != nil {
			runtime, err := configendorsement.RuntimeFromConfig(config)
			if err != nil {
				return nil, err
			}
			if runtime != *s.Predicate.Runtime {
				return nil, fmt.Errorf("config runtime does not match the endorsed runtime")
			}
		}
	}
	digest, err := hex.DecodeString(hexDigest)
	if err != nil {
		return nil, err
	}
	cryptographic := v.cryptographic
	authority := ScopeVerified{Identity: scope.Identity{Namespace: strings.Split(identity, "/")[1]}}
	if certificate != nil {
		verified, err := v.scopes.Verify(*certificate, s.Subject[0].Name, policy.Now)
		if err != nil {
			return nil, err
		}
		authority = *verified
		cryptographic, err = newEndorsementVerifier(v.cryptographic.trust, []crypto.PublicKey{authority.PublicKey})
		if err != nil {
			return nil, err
		}
	}
	hint, err := cryptographic.Verify(b, digest)
	if err != nil {
		return nil, err
	}
	if err := policy.Scope.Match(authority.Identity, hint); err != nil {
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
	if certificate != nil && (inner.Before(authority.ValidFrom) || inner.After(authority.ExpiresAt)) {
		return nil, fmt.Errorf("config approval falls outside scope authorization")
	}
	return &ConfigVerified{
		Name: s.Subject[0].Name, Digest: hexDigest,
		Reference: statement.EndorsementReference(payload), SigningKeyHint: hint, ApprovalTime: inner,
		Runtime: s.Predicate.Runtime,
		Scope:   authority.Identity, ScopeExpiresAt: authority.ExpiresAt,
	}, nil
}

func (c *Client) ConfigVerifier(keys []crypto.PublicKey) (*ConfigVerifier, error) {
	return NewConfigVerifier(c.trustRoot, keys)
}

func (c *Client) RegistryVerifier(keys, rootKeys []crypto.PublicKey) (*ConfigVerifier, error) {
	return NewRegistryVerifier(c.trustRoot, keys, rootKeys)
}

func NewRegistryVerifier(trust root.TrustedMaterial, keys, rootKeys []crypto.PublicKey) (*ConfigVerifier, error) {
	v, err := NewConfigVerifier(trust, keys)
	if err != nil {
		return nil, err
	}
	v.scopes, err = NewScopeVerifier(trust, rootKeys)
	return v, err
}
