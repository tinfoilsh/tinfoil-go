package endorsement

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"slices"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	configendorsement "github.com/tinfoilsh/tinfoil-go/endorsement/config"
	"github.com/tinfoilsh/tinfoil-go/internal/statement"
)

// ConfigPolicy pins the identity and supplies the client's clock and freshness rules.
// Zero MaxAge and FutureSkew select the defaults; Now is required.
// ConfigVerified.ApprovalTime reports the authenticated time.
type ConfigPolicy struct {
	Identity    string
	Revision    string
	Digest      string
	Now         time.Time
	MaxAge      time.Duration
	FutureSkew  time.Duration
	RegistryIDs []string
}

type ConfigVerified struct {
	Name           string
	Digest         string
	Reference      string
	SigningKeyHint string
	ApprovalTime   time.Time
	Runtime        *configendorsement.RuntimeReference
	RegistryID     string
	SignatureTime  time.Time
}

type ConfigVerifier struct {
	cryptographic *endorsementVerifier
	rootKeys      []crypto.PublicKey
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
	if p.RegistryIDs != nil && len(p.RegistryIDs) == 0 {
		return fmt.Errorf("config registry IDs must not be empty")
	}
	for i, registryID := range p.RegistryIDs {
		if err := configendorsement.ValidateRegistryID(registryID); err != nil {
			return err
		}
		if slices.Contains(p.RegistryIDs[:i], registryID) {
			return fmt.Errorf("duplicate config registry ID")
		}
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
	return v.verify(config, bundleJSON, nil, policy)
}

func (v *ConfigVerifier) VerifyCertified(config, bundleJSON []byte, issuerDER []byte, policy ConfigPolicy) (*ConfigVerified, error) {
	if len(v.rootKeys) == 0 {
		return nil, fmt.Errorf("registry root trust is not configured")
	}
	if len(issuerDER) == 0 {
		return nil, fmt.Errorf("certified registry verification requires an issuer certificate")
	}
	return v.verify(config, bundleJSON, issuerDER, policy)
}

func (v *ConfigVerifier) verify(config, bundleJSON []byte, issuerDER []byte, policy ConfigPolicy) (*ConfigVerified, error) {
	if config != nil && (len(config) == 0 || len(config) > configendorsement.MaxConfigSize) {
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
	var registryID, hint string
	var signedAt time.Time
	if issuerDER != nil {
		if s.PredicateType != configendorsement.PredicateTypeV2 {
			return nil, fmt.Errorf("certified registry endorsement requires a v2 statement")
		}
		timestamps, err := verify.VerifySignedTimestampWithThreshold(b, v.cryptographic.trust, 1)
		if err != nil {
			return nil, err
		}
		signedAt = timestamps[0].Time
		if err := timePolicy.verify(signedAt); err != nil {
			return nil, err
		}
		cert, issuer, err := configendorsement.VerifySigningCertificate(b.GetVerificationMaterial().GetCertificate().GetRawBytes(), issuerDER, v.rootKeys, signedAt)
		if err != nil {
			return nil, err
		}
		registryID = cert.URIs[0].String()
		if registryID != s.Predicate.RegistryID {
			return nil, fmt.Errorf("certificate registry ID does not match signed registry ID")
		}
		material := certificateMaterial{TrustedMaterial: v.cryptographic.trust, issuer: issuer}
		verifier, err := verify.NewSignedEntityVerifier(material, verify.WithSignedTimestamps(1), verify.WithTransparencyLog(1))
		if err != nil {
			return nil, err
		}
		identity, err := verify.NewShortCertificateIdentity("", "^$", registryID, "")
		if err != nil {
			return nil, err
		}
		if _, err := verifier.Verify(b, verify.NewPolicy(verify.WithArtifactDigest(statement.DigestAlgorithm, digest), verify.WithCertificateIdentity(identity))); err != nil {
			return nil, err
		}
		hint, err = statement.KeyHint(cert.PublicKey)
		if err != nil {
			return nil, err
		}
	} else {
		if len(v.rootKeys) != 0 && s.PredicateType == configendorsement.PredicateTypeV2 {
			return nil, fmt.Errorf("v2 registry endorsement requires an issuer certificate")
		}
		hint, err = v.cryptographic.Verify(b, digest)
		if err != nil {
			return nil, err
		}
		if len(v.rootKeys) != 0 {
			registryID = configendorsement.PublicRegistryID
		}
	}
	if policy.RegistryIDs != nil && !slices.Contains(policy.RegistryIDs, registryID) {
		return nil, fmt.Errorf("config registry ID is not accepted by the caller")
	}
	input, err := s.TimestampInput()
	if err != nil {
		return nil, err
	}
	inner, err := v.cryptographic.VerifyTimestamp(s.Predicate.Freshness.RFC3161Timestamp, input, timePolicy)
	if err != nil {
		return nil, fmt.Errorf("inner timestamp: %w", err)
	}
	if !signedAt.IsZero() && inner.After(signedAt.Add(configendorsement.CertificateClockSkew)) {
		return nil, fmt.Errorf("approval timestamp follows signature timestamp")
	}
	verified := &ConfigVerified{
		Name: s.Subject[0].Name, Digest: hexDigest,
		Reference: statement.EndorsementReference(payload), SigningKeyHint: hint, ApprovalTime: inner,
		Runtime: s.Predicate.Runtime, RegistryID: registryID, SignatureTime: signedAt,
	}
	return verified, nil
}

func (c *Client) ConfigVerifier(keys []crypto.PublicKey) (*ConfigVerifier, error) {
	return NewConfigVerifier(c.trustRoot, keys)
}

func (c *Client) RegistryVerifier(rootKeys []crypto.PublicKey) (*ConfigVerifier, error) {
	return NewRegistryVerifier(c.trustRoot, rootKeys)
}

func NewRegistryVerifier(trust root.TrustedMaterial, rootKeys []crypto.PublicKey) (*ConfigVerifier, error) {
	v, err := NewConfigVerifier(trust, rootKeys)
	if err != nil {
		return nil, err
	}
	v.rootKeys = slices.Clone(rootKeys)
	return v, nil
}

type certificateMaterial struct {
	root.TrustedMaterial
	issuer *x509.Certificate
}

func (m certificateMaterial) FulcioCertificateAuthorities() []root.CertificateAuthority {
	return []root.CertificateAuthority{&root.FulcioCertificateAuthority{Root: m.issuer}}
}
