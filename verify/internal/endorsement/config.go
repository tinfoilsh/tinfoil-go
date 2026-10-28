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
}

type ConfigVerified struct {
	Name           string
	Digest         string
	Reference      string
	SigningKeyHint string
	ApprovalTime   time.Time
	Runtime        *configendorsement.RuntimeReference
}

type ConfigVerifier struct {
	cryptographic *endorsementVerifier
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
	if err := configendorsement.ValidateIdentity(p.Identity); err != nil {
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
	return newTimePolicy(p.Now, p.MaxAge, p.FutureSkew)
}

// Verify authenticates the config digest, any supplied bytes, approval identity, signing authority,
// an independent approval timestamp, and Rekor v2 inclusion. It never accesses a network.
func (v *ConfigVerifier) Verify(config, bundleJSON []byte, policy ConfigPolicy) (*ConfigVerified, error) {
	if len(config) > configendorsement.MaxConfigSize {
		return nil, fmt.Errorf("config size is outside allowed bounds")
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
	s, err := configendorsement.ParseStatement(payload)
	if err != nil {
		return nil, err
	}
	identity, revision, err := configendorsement.ParseName(s.Subject[0].Name)
	if err != nil {
		return nil, err
	}
	if identity != policy.Identity || (policy.Revision != "" && revision != policy.Revision) {
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
	hint, err := v.cryptographic.Verify(b, digest)
	if err != nil {
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
		Name: s.Subject[0].Name, Digest: hexDigest,
		Reference: statement.EndorsementReference(payload), SigningKeyHint: hint, ApprovalTime: inner,
		Runtime: s.Predicate.Runtime,
	}, nil
}

func (c *Client) ConfigVerifier(keys []crypto.PublicKey) (*ConfigVerifier, error) {
	return NewConfigVerifier(c.trustRoot, keys)
}
