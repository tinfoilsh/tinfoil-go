package endorsement

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/digitorus/timestamp"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/signature"
)

const (
	DefaultMaxAge           = 7 * 24 * time.Hour
	DefaultFutureSkew       = 5 * time.Minute
	SigstoreTimestampPolicy = "1.3.6.1.4.1.57264.2"
	maxLogReceipts          = 8
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

type authorizedKey struct {
	SigningKey
	verifier *root.ExpiringKey
}

type Verifier struct {
	trust root.TrustedMaterial
	keys  map[string]authorizedKey
}

// NewVerifier builds an offline verifier. The supplied roots authenticate TSA
// and Rekor evidence; only keys in signingKeys can authorize a config approval.
func NewVerifier(trust root.TrustedMaterial, signingKeys []SigningKey) (*Verifier, error) {
	if trust == nil || len(trust.RekorLogs()) == 0 || len(trust.TimestampingAuthorities()) == 0 {
		return nil, fmt.Errorf("Rekor and timestamp authority trust are required")
	}
	if len(signingKeys) == 0 {
		return nil, fmt.Errorf("at least one independently trusted signing key is required")
	}
	v := &Verifier{trust: trust, keys: make(map[string]authorizedKey, len(signingKeys))}
	for _, key := range signingKeys {
		if err := ValidateAuditScope(key.AuditScope); err != nil {
			return nil, err
		}
		hint, err := KeyHint(key.PublicKey)
		if err != nil {
			return nil, err
		}
		if _, exists := v.keys[hint]; exists {
			return nil, fmt.Errorf("duplicate signing key %s", hint)
		}
		der, err := x509.MarshalPKIXPublicKey(key.PublicKey)
		if err != nil {
			return nil, err
		}
		key.PublicKey, err = x509.ParsePKIXPublicKey(der)
		if err != nil {
			return nil, err
		}
		sv, err := signature.LoadVerifier(key.PublicKey, crypto.SHA256)
		if err != nil {
			return nil, fmt.Errorf("loading signing key: %w", err)
		}
		v.keys[hint] = authorizedKey{key, root.NewExpiringKey(sv, time.Time{}, time.Time{})}
	}
	return v, nil
}

type scopedMaterial struct {
	root.TrustedMaterial
	hint string
	key  *root.ExpiringKey
}

func (m scopedMaterial) PublicKeyVerifier(hint string) (root.TimeConstrainedVerifier, error) {
	if hint != m.hint {
		return nil, fmt.Errorf("untrusted signing key hint")
	}
	return m.key, nil
}

func (p Policy) normalized() (Policy, error) {
	if err := ValidateIdentity(p.Identity); err != nil {
		return p, err
	}
	if err := ValidateAuditScope(p.AuditScope); err != nil {
		return p, err
	}
	if p.Revision != "" {
		if _, _, err := ParseName(p.Identity + "/" + p.Revision); err != nil {
			return p, err
		}
	}
	if p.Digest != "" && !digestPattern.MatchString(p.Digest) {
		return p, fmt.Errorf("digest pin must be lowercase SHA-256")
	}
	if (p.Now.IsZero() && !p.IgnoreFreshness) || p.MaxAge < 0 || p.FutureSkew < 0 {
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

// Verify authenticates exact config bytes, approval identity, signing authority,
// an independent approval timestamp, and Rekor v2 inclusion. It never accesses a network.
func (v *Verifier) Verify(config, bundleJSON []byte, policy Policy) (*Verified, error) {
	return v.verify(config, bundleJSON, policy, true)
}

// VerifyPrepared checks an unpublished approval before its immutable bytes are
// persisted. It requires no log receipts and does not establish transparency.
// Only Verify can authenticate a published approval.
func (v *Verifier) VerifyPrepared(config, bundleJSON []byte, policy Policy) error {
	_, err := v.verify(config, bundleJSON, policy, false)
	return err
}

func (v *Verifier) verify(config, bundleJSON []byte, policy Policy, requirePublication bool) (*Verified, error) {
	policy, err := policy.normalized()
	if err != nil {
		return nil, err
	}
	if len(config) == 0 || len(config) > MaxConfigSize || len(bundleJSON) == 0 || len(bundleJSON) > MaxBundleSize {
		return nil, fmt.Errorf("config or bundle size is outside allowed bounds")
	}
	var b bundle.Bundle
	if err := b.UnmarshalJSON(bundleJSON); err != nil {
		return nil, fmt.Errorf("parsing endorsement bundle: %w", err)
	}
	if err := validateBundle(&b, requirePublication); err != nil {
		return nil, err
	}
	hint := b.GetVerificationMaterial().GetPublicKey().GetHint()
	key, ok := v.keys[hint]
	if !ok || key.AuditScope != policy.AuditScope {
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
	material := scopedMaterial{TrustedMaterial: v.trust, hint: hint, key: key.verifier}
	// Signing authority comes from the pinned key set. The signed inner token
	// independently establishes freshness.
	options := []verify.VerifierOption{verify.WithNoObserverTimestamps()}
	if requirePublication {
		options = append(options, verify.WithTransparencyLog(1))
	}
	verifier, err := verify.NewSignedEntityVerifier(material, options...)
	if err != nil {
		return nil, err
	}
	if _, err := verifier.Verify(&b, verify.NewPolicy(verify.WithArtifactDigest("sha256", digest[:]), verify.WithKey())); err != nil {
		return nil, fmt.Errorf("verifying endorsement bundle: %w", err)
	}
	input, err := s.TimestampInput()
	if err != nil {
		return nil, err
	}
	inner, err := verifyTimestamp(s.Predicate.Freshness.RFC3161Timestamp, input, v.trust)
	if err != nil {
		return nil, fmt.Errorf("inner timestamp: %w", err)
	}
	if err := verifyApprovalTime(inner, policy); err != nil {
		return nil, err
	}
	ref, err := EndorsementReference(payload)
	if err != nil {
		return nil, err
	}
	return &Verified{
		Name: s.Subject[0].Name, AuditScope: policy.AuditScope, Digest: hexDigest,
		Reference: ref, SigningKeyHint: hint, ApprovalTime: inner,
	}, nil
}

// VerifyTimestamp authenticates a prepared core's TSA response before a
// publisher signs it. This does not authenticate a config endorsement or bind
// the response to a particular signing key.
func (v *Verifier) VerifyTimestamp(input, response []byte, policy Policy) (time.Time, error) {
	policy, err := policy.normalized()
	if err != nil {
		return time.Time{}, err
	}
	at, err := verifyTimestamp(response, input, v.trust)
	if err != nil {
		return time.Time{}, err
	}
	if err := verifyApprovalTime(at, policy); err != nil {
		return time.Time{}, err
	}
	return at, nil
}

func validateBundle(b *bundle.Bundle, requirePublication bool) error {
	if b.GetMediaType() != BundleType || b.GetDsseEnvelope() == nil || b.GetDsseEnvelope().GetPayloadType() != PayloadType {
		return fmt.Errorf("expected a v0.3 config DSSE bundle")
	}
	vm := b.GetVerificationMaterial()
	if vm.GetPublicKey() == nil || vm.GetPublicKey().GetHint() == "" {
		return fmt.Errorf("expected an independently trusted public-key hint")
	}
	sigs := b.GetDsseEnvelope().GetSignatures()
	if len(sigs) != 1 || len(sigs[0].GetSig()) == 0 {
		return fmt.Errorf("config endorsement requires exactly one signature")
	}
	if sigs[0].GetKeyid() != "" && sigs[0].GetKeyid() != vm.GetPublicKey().GetHint() {
		return fmt.Errorf("DSSE key ID disagrees with key hint")
	}
	entries := vm.GetTlogEntries()
	if requirePublication && (len(entries) == 0 || len(entries) > maxLogReceipts) {
		return fmt.Errorf("config endorsement requires bounded Rekor inclusion evidence")
	}
	if !requirePublication && len(entries) != 0 {
		return fmt.Errorf("prepared config endorsement must not contain log receipts")
	}
	for _, entry := range entries {
		if entry.GetKindVersion().GetKind() != "hashedrekord" || entry.GetKindVersion().GetVersion() != "0.0.2" || entry.GetIntegratedTime() != 0 || entry.GetInclusionProof() == nil || entry.GetInclusionPromise() != nil {
			return fmt.Errorf("config endorsement requires Rekor v2 inclusion proofs")
		}
	}
	if len(vm.GetTimestampVerificationData().GetRfc3161Timestamps()) != 0 {
		return fmt.Errorf("config endorsement uses only its signed approval timestamp")
	}
	return nil
}

func verifyTimestamp(response, input []byte, trust root.TrustedMaterial) (time.Time, error) {
	if len(response) == 0 || len(response) > MaxTimestampSize || len(input) == 0 || len(input) > MaxStatementSize {
		return time.Time{}, fmt.Errorf("timestamp response or input size is outside allowed bounds")
	}
	ts, err := timestamp.ParseResponse(response)
	if err != nil {
		return time.Time{}, err
	}
	digest := sha256.Sum256(input)
	if ts.HashAlgorithm != crypto.SHA256 || !bytes.Equal(ts.HashedMessage, digest[:]) || ts.Policy.String() != SigstoreTimestampPolicy {
		return time.Time{}, fmt.Errorf("unexpected timestamp imprint, algorithm, or policy")
	}
	for _, authority := range trust.TimestampingAuthorities() {
		verified, err := authority.Verify(response, input)
		if err == nil && verified.Time.Equal(ts.Time) {
			return ts.Time, nil
		}
	}
	return time.Time{}, fmt.Errorf("no trusted timestamp authority authenticated the response")
}

func verifyApprovalTime(at time.Time, policy Policy) error {
	if policy.IgnoreFreshness {
		return nil
	}
	if at.Before(policy.Now.Add(-policy.MaxAge)) {
		return fmt.Errorf("config approval is too old")
	}
	if at.After(policy.Now.Add(policy.FutureSkew)) {
		return fmt.Errorf("timestamp is in the future")
	}
	return nil
}
