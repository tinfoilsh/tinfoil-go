package client

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/tinfoilsh/tinfoil-go/verifier/envelope"
	"github.com/tinfoilsh/tinfoil-go/verifier/measurement"
	"github.com/tinfoilsh/tinfoil-go/verifier/policy"
	"github.com/tinfoilsh/tinfoil-go/verifier/provenance"
	"github.com/tinfoilsh/tinfoil-go/verifier/quote"
)

// VerifiedDocumentV3 contains verified measurements, transport keys, and witness expiry.
type VerifiedDocumentV3 struct {
	ConfigRepo      string
	EnclaveHost     string
	Verifier        SoftwareIdentity
	VerifiedAt      string
	CodeDigest      string
	CodeTag         string
	CodeMeasurement *measurement.Measurement
	// EnclaveMeasurement carries the quote's authenticated registers,
	// proven to match the expectations.
	EnclaveMeasurement *measurement.Measurement
	// CryptoMaterial holds the endorsed key items (hash-bound into the quote).
	CryptoMaterial []envelope.CryptoMaterialItem
	// FreshnessExpiresAt is the earlier authenticated code/platform witness
	// deadline. Cached verification must not authorize new requests at or
	// after this time; re-verifying the same witness does not extend it.
	FreshnessExpiresAt time.Time
}

// TLSPublicKeyFP returns the endorsed TLS key fingerprint (the id=tls
// crypto_material entry), or an error if the document does not endorse one.
func (v *VerifiedDocumentV3) TLSPublicKeyFP() (string, error) {
	return v.cryptoMaterialData(envelope.CryptoMaterialIDTLS, envelope.KeySPKIFPSHA256V1Format)
}

// HPKEPublicKey returns the endorsed HPKE public key (the id=hpke
// crypto_material entry), or an error if the document does not endorse one.
func (v *VerifiedDocumentV3) HPKEPublicKey() (string, error) {
	return v.cryptoMaterialData(envelope.CryptoMaterialIDHPKE, envelope.KeyX25519HPKEV1Format)
}

func (v *VerifiedDocumentV3) cryptoMaterialData(id, format string) (string, error) {
	for _, item := range v.CryptoMaterial {
		if item.ID != id {
			continue
		}
		if item.Format != format {
			return "", fmt.Errorf("crypto_material item %q has format %q, want %q", id, item.Format, format)
		}
		return item.Data, nil
	}
	return "", fmt.Errorf("document endorses no %q crypto material", id)
}

func (v *VerifiedDocumentV3) validateTransportKeys() error {
	if _, err := v.TLSPublicKeyFP(); err != nil {
		return err
	}
	for _, item := range v.CryptoMaterial {
		if item.ID == envelope.CryptoMaterialIDHPKE {
			_, err := v.HPKEPublicKey()
			return err
		}
	}
	return nil
}

// VerifyDocumentV3 verifies a nonce-bound document with the supplied policy.
// A nil policy uses defaults. repo is a trusted owner/name[@tag][@sha256:digest].
// Callers must bind traffic to the returned keys and enforce FreshnessExpiresAt.
// With PinnedCode, repo must be empty and only platform provenance is verified.
func VerifyDocumentV3(docBytes, nonce []byte, repo string, opts *VerificationOptions) (*VerifiedDocumentV3, error) {
	options, err := opts.normalized(repo)
	if err != nil {
		return nil, err
	}
	doc, expectedReportData, err := envelope.Check(docBytes, nonce)
	if err != nil {
		return nil, fmt.Errorf("envelope: %w", err)
	}

	result := &VerifiedDocumentV3{}
	var endorsements *provenance.PlatformEndorsements
	var shape *policy.Shape
	if options.PinnedCode != nil {
		result.CodeMeasurement, err = pinnedCodeMeasurement(options.PinnedCode, doc.CPUEvidence.Format)
		if err != nil {
			return nil, fmt.Errorf("pinned code: %w", err)
		}
		shape = options.PinnedShape
		if shape == nil {
			if doc.CPUEvidence.Format == envelope.TDXQuoteV1Format {
				return nil, fmt.Errorf("a TDX workload pin requires PinnedShape")
			}
			shape = &policy.Shape{}
		}
		var witnessedAt time.Time
		endorsements, witnessedAt, err = authenticatePlatformReferenceValues(doc, options.FreshnessMaxAge)
		if err != nil {
			return nil, fmt.Errorf("reference values: %w", err)
		}
		result.ConfigRepo = PinnedNoRepo
		result.CodeDigest = PinnedNoDigest
		result.FreshnessExpiresAt = witnessedAt.Add(options.FreshnessMaxAge)
	} else {
		var code *provenance.Code
		code, endorsements, result.FreshnessExpiresAt, err = authenticateReferenceValues(doc, repo, options.FreshnessMaxAge)
		if err != nil {
			return nil, fmt.Errorf("reference values: %w", err)
		}
		result.CodeDigest, result.CodeTag, result.CodeMeasurement = code.Digest, code.Tag, code.Measurement
		shape = code.Shape
	}

	_, authenticated, err := quote.Verify(doc, endorsements.Artifact, result.CodeMeasurement, options.PinnedRegisters, shape, expectedReportData)
	if err != nil {
		return nil, fmt.Errorf("cpu evidence: %w", err)
	}

	result.EnclaveMeasurement = authenticated.Measurement
	result.CryptoMaterial = doc.CryptoMaterialItems()
	return result, nil
}

func authenticateReferenceValues(doc *envelope.Document, repo string, maxAge time.Duration) (*provenance.Code, *provenance.PlatformEndorsements, time.Time, error) {
	codeRef, err := doc.ReferenceValuesCollateral(envelope.CollateralSigstoreCodeV1Format)
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	code, err := provenance.AuthenticateCode(codeRef.SigstoreBundle, repo, codeRef.Tag, codeRef.Digest)
	if err != nil {
		return nil, nil, time.Time{}, fmt.Errorf("verifying code measurement: %w", err)
	}
	codeFreshnessRef, err := doc.FreshnessCollateral(envelope.FreshnessCollateralIDCode)
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	codeWitnessedAt, err := provenance.AuthenticateFreshness(codeFreshnessRef.SigstoreBundle, &code.AuthenticatedArtifact, time.Now(), maxAge)
	if err != nil {
		return nil, nil, time.Time{}, fmt.Errorf("verifying code freshness: %w", err)
	}

	endorsements, platformWitnessedAt, err := authenticatePlatformReferenceValues(doc, maxAge)
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	return code, endorsements, freshnessExpiration(codeWitnessedAt, platformWitnessedAt, maxAge), nil
}

func authenticatePlatformReferenceValues(doc *envelope.Document, maxAge time.Duration) (*provenance.PlatformEndorsements, time.Time, error) {
	platformRef, err := doc.ReferenceValuesCollateral(envelope.CollateralSigstorePlatformV1Format)
	if err != nil {
		return nil, time.Time{}, err
	}
	endorsements, err := provenance.AuthenticatePlatformEndorsements(platformRef.SigstoreBundle, platformRef.Repo, platformRef.Tag, platformRef.Digest)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("verifying platform endorsements: %w", err)
	}
	freshnessRef, err := doc.FreshnessCollateral(envelope.FreshnessCollateralIDPlatform)
	if err != nil {
		return nil, time.Time{}, err
	}
	platformWitnessedAt, err := provenance.AuthenticateFreshness(freshnessRef.SigstoreBundle, &endorsements.AuthenticatedArtifact, time.Now(), maxAge)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("verifying platform freshness: %w", err)
	}

	return endorsements, platformWitnessedAt, nil
}

// freshnessExpiration uses authenticated witness times, never local verification time.
func freshnessExpiration(codeWitnessedAt, platformWitnessedAt time.Time, maxAge time.Duration) time.Time {
	expiresAt := codeWitnessedAt.Add(maxAge)
	platformExpiresAt := platformWitnessedAt.Add(maxAge)
	if platformExpiresAt.Before(expiresAt) {
		expiresAt = platformExpiresAt
	}
	return expiresAt
}

func (s *SecureClient) fetchVerification() (*VerifiedDocumentV3, error) {
	nonce, err := envelope.RandomNonce()
	if err != nil {
		return nil, err
	}
	docBytes, err := envelope.Fetch(s.enclave, nonce)
	if err != nil {
		return nil, fmt.Errorf("fetching attestation document: %w", err)
	}

	verified, err := VerifyDocumentV3(docBytes, nonce, s.repo, &s.options)
	if err != nil {
		return nil, err
	}

	if err := verified.validateTransportKeys(); err != nil {
		return nil, fmt.Errorf("binding: %w", err)
	}
	if s.options.PinnedCode == nil {
		verified.ConfigRepo, _, _ = strings.Cut(s.repo, "@")
	}
	verified.EnclaveHost = s.enclave
	verified.Verifier = currentVerifierIdentity()
	verified.VerifiedAt = time.Now().UTC().Format(time.RFC3339Nano)
	return verified, nil
}

// Verify refreshes the client's verified measurements and keys.
func (s *SecureClient) Verify() (*VerifiedDocumentV3, error) {
	state, err := s.verifiedState(context.Background(), nil, true)
	if err != nil {
		return nil, err
	}
	return cloneVerification(state), nil
}
