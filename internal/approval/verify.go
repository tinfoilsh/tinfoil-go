// Package approval contains shared Sigstore approval verification.
package approval

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/digitorus/timestamp"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/signature"
)

const (
	PayloadType             = "application/vnd.in-toto+json"
	BundleType              = "application/vnd.dev.sigstore.bundle.v0.3+json"
	MaxBundleSize           = 4 << 20
	MaxStatementSize        = 128 << 10
	MaxTimestampSize        = 64 << 10
	SigstoreTimestampPolicy = "1.3.6.1.4.1.57264.2"
	maxLogReceipts          = 8
)

type Verifier struct {
	trust root.TrustedMaterial
	keys  map[string]*root.ExpiringKey
}

func NewVerifier(trust root.TrustedMaterial, keys []crypto.PublicKey) (*Verifier, error) {
	if trust == nil || len(trust.RekorLogs()) == 0 || len(trust.TimestampingAuthorities()) == 0 {
		return nil, fmt.Errorf("Rekor and timestamp authority trust are required")
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("at least one independently trusted signing key is required")
	}
	v := &Verifier{trust: trust, keys: make(map[string]*root.ExpiringKey, len(keys))}
	for _, key := range keys {
		hint, err := KeyHint(key)
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

func ParseBundle(raw []byte, published bool) (*bundle.Bundle, error) {
	if len(raw) == 0 || len(raw) > MaxBundleSize {
		return nil, fmt.Errorf("bundle size is outside allowed bounds")
	}
	var b bundle.Bundle
	if err := b.UnmarshalJSON(raw); err != nil {
		return nil, fmt.Errorf("parsing endorsement bundle: %w", err)
	}
	if err := validateBundle(&b, published); err != nil {
		return nil, err
	}
	return &b, nil
}

func (v *Verifier) Verify(b *bundle.Bundle, digest []byte, published bool) (string, error) {
	hint := b.GetVerificationMaterial().GetPublicKey().GetHint()
	key, ok := v.keys[hint]
	if !ok {
		return "", fmt.Errorf("untrusted approval signing key")
	}
	material := scopedMaterial{TrustedMaterial: v.trust, hint: hint, key: key}
	// Signing authority comes from the pinned key set. The signed inner token
	// independently establishes freshness.
	options := []verify.VerifierOption{verify.WithNoObserverTimestamps()}
	if published {
		options = append(options, verify.WithTransparencyLog(1))
	}
	verifier, err := verify.NewSignedEntityVerifier(material, options...)
	if err != nil {
		return "", err
	}
	if _, err := verifier.Verify(b, verify.NewPolicy(verify.WithArtifactDigest("sha256", digest), verify.WithKey())); err != nil {
		return "", fmt.Errorf("verifying endorsement bundle: %w", err)
	}
	return hint, nil
}

func (v *Verifier) VerifyTimestamp(response, input []byte) (time.Time, error) {
	return VerifyTimestamp(response, input, v.trust)
}

func KeyHint(publicKey crypto.PublicKey) (string, error) {
	key, ok := publicKey.(*ecdsa.PublicKey)
	if !ok || key == nil || key.Curve != elliptic.P256() || key.X == nil || key.Y == nil || !key.Curve.IsOnCurve(key.X, key.Y) {
		return "", fmt.Errorf("approval requires an ECDSA P-256 key")
	}
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", fmt.Errorf("encoding signing key: %w", err)
	}
	digest := sha256.Sum256(der)
	return base64.StdEncoding.EncodeToString(digest[:]), nil
}

func validateBundle(b *bundle.Bundle, requirePublication bool) error {
	if b.GetMediaType() != BundleType || b.GetDsseEnvelope() == nil || b.GetDsseEnvelope().GetPayloadType() != PayloadType {
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
	if requirePublication && (len(entries) == 0 || len(entries) > maxLogReceipts) {
		return fmt.Errorf("approval requires bounded Rekor inclusion evidence")
	}
	if !requirePublication && len(entries) != 0 {
		return fmt.Errorf("prepared approval must not contain log receipts")
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

func VerifyTimestamp(response, input []byte, trust root.TrustedMaterial) (time.Time, error) {
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
