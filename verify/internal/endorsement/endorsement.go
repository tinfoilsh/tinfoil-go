package endorsement

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/signature"

	"github.com/tinfoilsh/tinfoil-go/internal/statement"
)

const (
	SigstoreTimestampPolicy = "1.3.6.1.4.1.57264.2"
	maxLogReceipts          = 8
)

type endorsementVerifier struct {
	trust root.TrustedMaterial
	keys  map[string]*root.ExpiringKey
}

func newEndorsementVerifier(trust root.TrustedMaterial, keys []crypto.PublicKey) (*endorsementVerifier, error) {
	if trust == nil || len(trust.RekorLogs()) == 0 {
		return nil, fmt.Errorf("Rekor trust is required")
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("at least one independently trusted signing key is required")
	}
	v := &endorsementVerifier{trust: trust, keys: make(map[string]*root.ExpiringKey, len(keys))}
	for _, key := range keys {
		hint, err := statement.KeyHint(key)
		if err != nil {
			return nil, err
		}
		if _, exists := v.keys[hint]; exists {
			return nil, fmt.Errorf("duplicate signing key %s", hint)
		}
		der, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			return nil, err
		}
		key, err = x509.ParsePKIXPublicKey(der)
		if err != nil {
			return nil, err
		}
		sv, err := signature.LoadVerifier(key, crypto.SHA256)
		if err != nil {
			return nil, fmt.Errorf("loading signing key: %w", err)
		}
		v.keys[hint] = root.NewExpiringKey(sv, time.Time{}, time.Time{})
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

func parseEndorsementBundle(raw []byte) (*bundle.Bundle, error) {
	if len(raw) == 0 || len(raw) > statement.MaxBundleSize {
		return nil, fmt.Errorf("bundle size is outside allowed bounds")
	}
	var b bundle.Bundle
	if err := b.UnmarshalJSON(raw); err != nil {
		return nil, fmt.Errorf("parsing endorsement bundle: %w", err)
	}
	if err := validateEndorsementBundle(&b); err != nil {
		return nil, err
	}
	return &b, nil
}

func (v *endorsementVerifier) Verify(b *bundle.Bundle, digest []byte) (string, error) {
	hint := b.GetVerificationMaterial().GetPublicKey().GetHint()
	key, ok := v.keys[hint]
	if !ok {
		return "", fmt.Errorf("untrusted approval signing key")
	}
	material := scopedMaterial{TrustedMaterial: v.trust, hint: hint, key: key}
	// Signing authority comes from the pinned key set. The signed inner token
	// independently establishes freshness.
	verifier, err := verify.NewSignedEntityVerifier(material, verify.WithNoObserverTimestamps(), verify.WithTransparencyLog(1))
	if err != nil {
		return "", err
	}
	if _, err := verifier.Verify(b, verify.NewPolicy(verify.WithArtifactDigest(statement.DigestAlgorithm, digest), verify.WithKey())); err != nil {
		return "", fmt.Errorf("verifying endorsement bundle: %w", err)
	}
	return hint, nil
}

func validateEndorsementBundle(b *bundle.Bundle) error {
	if b.GetMediaType() != statement.BundleType || b.GetDsseEnvelope() == nil || b.GetDsseEnvelope().GetPayloadType() != statement.PayloadType {
		return fmt.Errorf("expected a v0.3 approval DSSE bundle")
	}
	vm := b.GetVerificationMaterial()
	if vm.GetPublicKey() == nil || vm.GetPublicKey().GetHint() == "" {
		return fmt.Errorf("expected an independently trusted public-key hint")
	}
	sigs := b.GetDsseEnvelope().GetSignatures()
	if len(sigs) != 1 || len(sigs[0].GetSig()) == 0 {
		return fmt.Errorf("approval requires exactly one signature")
	}
	if sigs[0].GetKeyid() != "" && sigs[0].GetKeyid() != vm.GetPublicKey().GetHint() {
		return fmt.Errorf("DSSE key ID disagrees with key hint")
	}
	entries := vm.GetTlogEntries()
	if len(entries) == 0 || len(entries) > maxLogReceipts {
		return fmt.Errorf("approval requires bounded Rekor inclusion evidence")
	}
	for _, entry := range entries {
		if entry.GetKindVersion().GetKind() != "hashedrekord" || entry.GetKindVersion().GetVersion() != "0.0.2" || entry.GetIntegratedTime() != 0 || entry.GetInclusionProof() == nil || entry.GetInclusionPromise() != nil {
			return fmt.Errorf("approval requires Rekor v2 inclusion proofs")
		}
	}
	if len(vm.GetTimestampVerificationData().GetRfc3161Timestamps()) != 0 {
		return fmt.Errorf("approval uses only its signed approval timestamp")
	}
	return nil
}

func (v *endorsementVerifier) VerifyTimestamp(response, input []byte, policy timePolicy) (time.Time, error) {
	if len(input) == 0 || len(input) > statement.MaxStatementSize {
		return time.Time{}, fmt.Errorf("timestamp input size is outside allowed bounds")
	}
	ts, err := statement.ParseTimestamp(response, input)
	if err != nil {
		return time.Time{}, err
	}
	if ts.Policy.String() != SigstoreTimestampPolicy {
		return time.Time{}, fmt.Errorf("unexpected timestamp policy")
	}
	for _, authority := range v.trust.TimestampingAuthorities() {
		verified, err := authority.Verify(response, input)
		if err == nil && verified.Time.Equal(ts.Time) {
			if err := policy.verify(ts.Time); err != nil {
				return time.Time{}, err
			}
			return ts.Time, nil
		}
	}
	return time.Time{}, fmt.Errorf("no trusted timestamp authority authenticated the response")
}
