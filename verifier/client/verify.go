package client

import (
	"cmp"
	"context"
	"fmt"
	"time"

	"github.com/tinfoilsh/tinfoil-go/verifier/envelope"
	"github.com/tinfoilsh/tinfoil-go/verifier/measurement"
	"github.com/tinfoilsh/tinfoil-go/verifier/provenance"
	"github.com/tinfoilsh/tinfoil-go/verifier/quote"
)

// VerifiedDocumentV3 is what a verified v3 document proves. The operative
// output is CryptoMaterial — the endorsed keys a caller may bind a channel
// to; it is the only field that authorizes an action. The remaining fields
// feed the client's ground truth.
type VerifiedDocumentV3 struct {
	// CodeRepo, CodeTag, and CodeDigest name the verified code artifact;
	// CodeMeasurement is the expected measurement applied from it.
	CodeRepo        string
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

// transportKeys recovers keys after document verification. TLS is required
// by SecureClient; HPKE is optional until the caller selects EHBP.
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

// VerifyDocumentV3 verifies a v3 attestation document from its transmitted
// bytes:
//
//  1. Check the envelope: format, nonce equality, endorsed-section hash
//     recomputation, REPORT_DATA recomputation (no authentication).
//  2. Authenticate the reference values: the sigstore-code and
//     sigstore-platform, and sigstore-freshness entries against pinned signing
//     identities, recovering the code measurement, its declared VM shape,
//     the policy artifact, and its current freshness proof.
//  3. Verify the CPU quote: authenticate against the pinned vendor roots,
//     assemble the complete policy from the reference values, validate in
//     one call.
//
// repo is the code repository the caller trusts (pins the sigstore-code
// signing identity); the repo named inside the document is not trusted.
// repo may pin a tag or digest, owner/name[@tag][@sha256:digest]; expected pins registers.
// Channel binding (TLS fingerprint / HPKE key) is the caller's
// responsibility, using the returned endorsed crypto material.
func VerifyDocumentV3(docBytes, nonce []byte, repo string, expected *measurement.Measurement) (*VerifiedDocumentV3, error) {
	doc, expectedReportData, err := envelope.Check(docBytes, nonce)
	if err != nil {
		return nil, fmt.Errorf("envelope: %w", err)
	}

	code, endorsements, freshnessExpiresAt, err := authenticateReferenceValues(doc, repo)
	if err != nil {
		return nil, fmt.Errorf("reference values: %w", err)
	}

	_, authenticated, err := quote.Verify(doc, endorsements.Artifact, code.Measurement, expected, code.Shape, expectedReportData)
	if err != nil {
		return nil, fmt.Errorf("cpu evidence: %w", err)
	}

	return &VerifiedDocumentV3{
		CodeRepo:           code.Repo,
		CodeDigest:         code.Digest,
		CodeTag:            code.Tag,
		CodeMeasurement:    code.Measurement,
		EnclaveMeasurement: authenticated.Measurement,
		CryptoMaterial:     doc.CryptoMaterialItems(),
		FreshnessExpiresAt: freshnessExpiresAt,
	}, nil
}

// authenticateReferenceValues authenticates the document's required code and
// platform Sigstore artifacts plus the matching freshness proof for each,
// returning the authenticated code, platform values, and the earlier of their
// authenticated freshness expiration times.
func authenticateReferenceValues(doc *envelope.Document, repo string) (*provenance.Code, *provenance.PlatformEndorsements, time.Time, error) {
	release, err := provenance.ParseRef(repo)
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	codeRef, err := doc.ReferenceValuesCollateral(envelope.CollateralSigstoreCodeV1Format)
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	code, err := provenance.AuthenticateCode(codeRef.SigstoreBundle, release.Repo, cmp.Or(release.Tag, codeRef.Tag), cmp.Or(release.Digest, codeRef.Digest))
	if err != nil {
		return nil, nil, time.Time{}, fmt.Errorf("verifying code measurement: %w", err)
	}
	codeFreshnessRef, err := doc.FreshnessCollateral(envelope.FreshnessCollateralIDCode)
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	appraisalTime := time.Now()
	codeWitnessedAt, err := provenance.AuthenticateFreshness(codeFreshnessRef.SigstoreBundle, &code.AuthenticatedArtifact, appraisalTime)
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
	platformWitnessedAt, err := provenance.AuthenticateFreshness(freshnessRef.SigstoreBundle, &endorsements.AuthenticatedArtifact, appraisalTime)
	if err != nil {
		return nil, nil, time.Time{}, fmt.Errorf("verifying platform freshness: %w", err)
	}

	return code, endorsements, freshnessExpiration(codeWitnessedAt, platformWitnessedAt), nil
}

// freshnessExpiration uses authenticated witness times, never local verification time.
func freshnessExpiration(codeWitnessedAt, platformWitnessedAt time.Time) time.Time {
	expiresAt := codeWitnessedAt.Add(provenance.MaxFreshnessAge)
	platformExpiresAt := platformWitnessedAt.Add(provenance.MaxFreshnessAge)
	if platformExpiresAt.Before(expiresAt) {
		expiresAt = platformExpiresAt
	}
	return expiresAt
}

// VerifyV3 runs the single-request v3 flow against the client's enclave:
// generate a fresh nonce, fetch the document (evidence + collateral) in one
// request, verify it, and recover its endorsed transport keys. On success the
// client's ground truth is updated so the first and every subsequent request
// enforce the endorsed TLS or HPKE key.
//
// The enclave fetch is the only network request: all collateral travels in
// the document and Sigstore verification uses the embedded trust root.
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

	verified, err := VerifyDocumentV3(docBytes, nonce, s.repo, s.expectedMeasurement)
	if err != nil {
		return nil, err
	}

	// Recover the transport keys bound into the verified CPU report. The
	// selected transport enforces its key before sending the first request.
	tlsFP, hpkeKey, err := verified.transportKeys()
	if err != nil {
		return nil, fmt.Errorf("binding: %w", err)
	}
	groundTruth := &GroundTruth{
		ConfigRepo:         verified.CodeRepo,
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
	return &verificationState{
		verified: verified, groundTruth: groundTruth,
		document: newVerificationDocument(groundTruth),
	}, nil
}

// Verify attests the enclave with the v3 single-request flow and stores the
// resulting ground truth in the client.
func (s *SecureClient) Verify() (*GroundTruth, error) {
	state, err := s.verifiedState(context.Background(), nil, true)
	if err != nil {
		return nil, err
	}
	return cloneGroundTruth(state.groundTruth), nil
}
