package client

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/tinfoilsh/tinfoil-go/verifier/envelope"
	"github.com/tinfoilsh/tinfoil-go/verifier/measurement"
	"github.com/tinfoilsh/tinfoil-go/verifier/provenance"
	"github.com/tinfoilsh/tinfoil-go/verifier/quote"
)

// VerifiedDocumentV3 contains verified measurements, transport keys, and witness expiry.
type VerifiedDocumentV3 struct {
	CodeDigest      string
	CodeTag         string
	CodeMeasurement *measurement.Measurement
	// EnclaveMeasurement contains the authenticated registers after policy checks.
	EnclaveMeasurement *measurement.Measurement
	// CryptoMaterial contains keys bound to the quote by REPORT_DATA.
	CryptoMaterial []envelope.CryptoMaterialItem
	// FreshnessExpiresAt is the earlier authenticated code/platform witness
	// deadline. Cached verification must not authorize new requests at or
	// after this time; re-verifying the same witness does not extend it.
	FreshnessExpiresAt time.Time
}

// TLSPublicKeyFP returns the attested TLS key fingerprint, or an error if absent.
func (v *VerifiedDocumentV3) TLSPublicKeyFP() (string, error) {
	return v.cryptoMaterialData(envelope.CryptoMaterialIDTLS, envelope.KeySPKIFPSHA256V1Format)
}

// HPKEPublicKey returns the attested HPKE public key, or an error if absent.
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

// SecureClient requires TLS; EHBP also requires HPKE.
func (v *VerifiedDocumentV3) transportKeys() (tlsFP, hpkeKey string, err error) {
	tlsFP, err = v.TLSPublicKeyFP()
	if err != nil {
		return "", "", err
	}
	for _, item := range v.CryptoMaterial {
		if item.ID == envelope.CryptoMaterialIDHPKE {
			hpkeKey, err = v.HPKEPublicKey()
			return tlsFP, hpkeKey, err
		}
	}
	return tlsFP, "", nil
}

// VerifyDocumentV3 checks the nonce, section hashes, provenance, witnesses, and CPU quote.
// repo is the caller's trusted owner/name[@tag][@sha256:digest] reference.
// Callers must bind traffic to the returned TLS/HPKE keys and enforce FreshnessExpiresAt.
func VerifyDocumentV3(docBytes, nonce []byte, repo string) (*VerifiedDocumentV3, error) {
	return VerifyDocumentV3WithOptions(docBytes, nonce, repo, VerificationOptions{})
}

// VerifyDocumentV3WithOptions applies opts to the same checks as VerifyDocumentV3.
// Callers must bind traffic to the returned keys and enforce FreshnessExpiresAt.
func VerifyDocumentV3WithOptions(docBytes, nonce []byte, repo string, opts VerificationOptions) (*VerifiedDocumentV3, error) {
	opts, err := opts.normalized()
	if err != nil {
		return nil, err
	}
	doc, expectedReportData, err := envelope.Check(docBytes, nonce)
	if err != nil {
		return nil, fmt.Errorf("envelope: %w", err)
	}

	code, endorsements, freshnessExpiresAt, err := authenticateReferenceValues(doc, repo, opts.FreshnessMaxAge)
	if err != nil {
		return nil, fmt.Errorf("reference values: %w", err)
	}

	_, authenticated, err := quote.Verify(doc, endorsements.Artifact, code.Measurement, opts.PinnedRegisters, code.Shape, expectedReportData)
	if err != nil {
		return nil, fmt.Errorf("cpu evidence: %w", err)
	}

	return &VerifiedDocumentV3{
		CodeDigest:         code.Digest,
		CodeTag:            code.Tag,
		CodeMeasurement:    code.Measurement,
		EnclaveMeasurement: authenticated.Measurement,
		CryptoMaterial:     doc.CryptoMaterialItems(),
		FreshnessExpiresAt: freshnessExpiresAt,
	}, nil
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
	appraisalTime := time.Now()
	codeWitnessedAt, err := provenance.AuthenticateFreshnessWithMaxAge(codeFreshnessRef.SigstoreBundle, &code.AuthenticatedArtifact, appraisalTime, maxAge)
	if err != nil {
		return nil, nil, time.Time{}, fmt.Errorf("verifying code freshness: %w", err)
	}

	platformRef, err := doc.ReferenceValuesCollateral(envelope.CollateralSigstorePlatformV1Format)
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	endorsements, err := provenance.AuthenticatePlatformEndorsements(platformRef.SigstoreBundle, platformRef.Repo, platformRef.Tag, platformRef.Digest)
	if err != nil {
		return nil, nil, time.Time{}, fmt.Errorf("verifying platform endorsements: %w", err)
	}
	freshnessRef, err := doc.FreshnessCollateral(envelope.FreshnessCollateralIDPlatform)
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	platformWitnessedAt, err := provenance.AuthenticateFreshnessWithMaxAge(freshnessRef.SigstoreBundle, &endorsements.AuthenticatedArtifact, appraisalTime, maxAge)
	if err != nil {
		return nil, nil, time.Time{}, fmt.Errorf("verifying platform freshness: %w", err)
	}

	return code, endorsements, freshnessExpiration(codeWitnessedAt, platformWitnessedAt, maxAge), nil
}

func freshnessExpiration(codeWitnessedAt, platformWitnessedAt time.Time, maxAge time.Duration) time.Time {
	if platformWitnessedAt.Before(codeWitnessedAt) {
		codeWitnessedAt = platformWitnessedAt
	}
	return codeWitnessedAt.Add(maxAge)
}

// VerifyV3 fetches and verifies a nonce-bound document, then caches the result.
// Verification uses embedded roots and collateral from the document.
func (s *SecureClient) VerifyV3() (*VerifiedDocumentV3, error) {
	state, err := s.verifiedState(context.Background(), nil, true)
	if err != nil {
		return nil, err
	}
	result := *state.verified
	result.CodeMeasurement = cloneMeasurement(result.CodeMeasurement)
	result.EnclaveMeasurement = cloneMeasurement(result.EnclaveMeasurement)
	result.CryptoMaterial = append([]envelope.CryptoMaterialItem(nil), result.CryptoMaterial...)
	return &result, nil
}

func (s *SecureClient) fetchVerification() (*verificationState, error) {
	nonce, err := envelope.RandomNonce()
	if err != nil {
		return nil, err
	}
	docBytes, err := envelope.Fetch(s.enclave, nonce)
	if err != nil {
		return nil, fmt.Errorf("fetching attestation document: %w", err)
	}

	verified, err := VerifyDocumentV3WithOptions(docBytes, nonce, s.repo, s.options)
	if err != nil {
		return nil, err
	}

	tlsFP, hpkeKey, err := verified.transportKeys()
	if err != nil {
		return nil, fmt.Errorf("binding: %w", err)
	}
	repo, _, _ := strings.Cut(s.repo, "@")
	groundTruth := &GroundTruth{
		ConfigRepo:         repo,
		EnclaveHost:        s.enclave,
		ReleaseTag:         verified.CodeTag,
		TLSPublicKey:       tlsFP,
		HPKEPublicKey:      hpkeKey,
		Digest:             verified.CodeDigest,
		CodeMeasurement:    verified.CodeMeasurement,
		EnclaveMeasurement: verified.EnclaveMeasurement,
		CodeFingerprint:    verified.CodeMeasurement.Fingerprint(),
		EnclaveFingerprint: verified.EnclaveMeasurement.Fingerprint(),
		Verifier:           currentVerifierIdentity(),
		VerifiedAt:         verificationTime().UTC().Format(time.RFC3339Nano),
	}
	return &verificationState{verified: verified, groundTruth: groundTruth}, nil
}

// Verify refreshes the client's verified measurements and keys.
func (s *SecureClient) Verify() (*GroundTruth, error) {
	state, err := s.verifiedState(context.Background(), nil, true)
	if err != nil {
		return nil, err
	}
	return cloneGroundTruth(state.groundTruth), nil
}
