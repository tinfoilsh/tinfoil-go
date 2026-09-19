package client

import (
	"fmt"
	"time"

	"github.com/tinfoilsh/tinfoil-go/verifier/envelope"
	"github.com/tinfoilsh/tinfoil-go/verifier/measurement"
	"github.com/tinfoilsh/tinfoil-go/verifier/policy"
	"github.com/tinfoilsh/tinfoil-go/verifier/provenance"
	"github.com/tinfoilsh/tinfoil-go/verifier/quote"
)

// VerifiedDocumentV3 is what a verified v3 document proves. The operative
// output is CryptoMaterial — the endorsed keys a caller may bind a channel
// to; it is the only field that authorizes an action. The remaining fields
// feed the client's ground truth.
type VerifiedDocumentV3 struct {
	// CodeDigest names the verified code artifact; CodeMeasurement is the
	// expected measurement applied from it.
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
// Channel binding (TLS fingerprint / HPKE key) is the caller's
// responsibility, using the returned endorsed crypto material.
func VerifyDocumentV3(docBytes, nonce []byte, repo string) (*VerifiedDocumentV3, error) {
	doc, expectedReportData, err := envelope.Check(docBytes, nonce)
	if err != nil {
		return nil, fmt.Errorf("envelope: %w", err)
	}

	code, endorsements, freshnessExpiresAt, err := authenticateReferenceValues(doc, repo)
	if err != nil {
		return nil, fmt.Errorf("reference values: %w", err)
	}

	_, authenticated, err := quote.Verify(doc, endorsements.Artifact, code.Measurement, code.Shape, expectedReportData)
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

// Pin is a caller-supplied expected code measurement that replaces the
// document's Sigstore code provenance. Pinning skips only the code-provenance
// lookup: the platform endorsements, their freshness proof, the CPU quote
// chain, REPORT_DATA binding, and channel binding are all still verified.
//
// The measurement's provenance is the caller's responsibility. A TDX pin
// (TdxGuestV2 or SnpTdxMultiPlatformV1 targeting a TDX enclave) must also
// declare the VM shape the code was built for, because v3 resolves the
// endorsed platform measurement under that shape and the code artifact that
// normally carries it is not consulted.
type Pin struct {
	Measurement *measurement.Measurement
	// Shape is required when the enclave is TDX; ignored for SEV-SNP.
	Shape *policy.Shape
}

// PinnedNoDigest is recorded as the release digest when the code measurement
// was pinned by the caller rather than proven by a release artifact.
const PinnedNoDigest = "pinned_no_digest"

// PinnedNoRepo is recorded as the config repository when the code measurement
// was pinned by the caller and no repository's provenance was consulted.
const PinnedNoRepo = "pinned_no_repo"

// NewPin validates and copies a caller-supplied measurement and optional VM
// shape. The returned Pin is independent of the caller's values.
func NewPin(m *measurement.Measurement, shape *policy.Shape) (*Pin, error) {
	validated, err := measurement.ValidatePin(m)
	if err != nil {
		return nil, fmt.Errorf("invalid pinned measurement: %w", err)
	}
	if validated.Type == measurement.TdxGuestV2 && shape == nil {
		return nil, fmt.Errorf("a TDX pin requires a VM shape")
	}
	pin := &Pin{Measurement: validated}
	if shape != nil {
		// Match the non-negative dimensions accepted by v3 code provenance.
		if shape.CPUs < 0 || shape.MemoryMB < 0 || shape.Disks < 0 || (shape.GPUs != nil && *shape.GPUs < 0) {
			return nil, fmt.Errorf("invalid pinned VM shape: dimensions must be non-negative")
		}
		copied := *shape
		if shape.GPUs != nil {
			gpus := *shape.GPUs
			copied.GPUs = &gpus
		}
		pin.Shape = &copied
	}
	return pin, nil
}

// VerifyDocumentV3Pinned verifies a v3 attestation document against a
// caller-pinned code measurement. It performs every check VerifyDocumentV3
// does except authenticating the sigstore-code reference value: the platform
// endorsements and their freshness are still authenticated, the quote is
// still verified against pinned vendor roots, and its registers are compared
// against the pin. FreshnessExpiresAt reflects the platform witness only.
func VerifyDocumentV3Pinned(docBytes, nonce []byte, pin *Pin) (*VerifiedDocumentV3, error) {
	if pin == nil || pin.Measurement == nil {
		return nil, fmt.Errorf("pinned verification requires a pin")
	}
	validated, err := NewPin(pin.Measurement, pin.Shape)
	if err != nil {
		return nil, err
	}
	pin = validated
	doc, expectedReportData, err := envelope.Check(docBytes, nonce)
	if err != nil {
		return nil, fmt.Errorf("envelope: %w", err)
	}

	endorsements, platformWitnessedAt, err := authenticatePlatformReferenceValues(doc, time.Now())
	if err != nil {
		return nil, fmt.Errorf("reference values: %w", err)
	}

	// quote.Assemble requires a shape unconditionally; SEV-SNP never reads it,
	// so a placeholder keeps the SEV path free of an unused caller input while
	// TDX still fails closed when the caller did not declare one.
	shape := pin.Shape
	if shape == nil {
		if doc.CPUEvidence.Format == envelope.TDXQuoteV1Format {
			return nil, fmt.Errorf("cpu evidence: a TDX enclave requires the pin to declare the VM shape")
		}
		shape = &policy.Shape{}
	}
	_, authenticated, err := quote.Verify(doc, endorsements.Artifact, pin.Measurement, shape, expectedReportData)
	if err != nil {
		return nil, fmt.Errorf("cpu evidence: %w", err)
	}

	return &VerifiedDocumentV3{
		CodeDigest:         PinnedNoDigest,
		CodeMeasurement:    cloneMeasurement(pin.Measurement),
		EnclaveMeasurement: authenticated.Measurement,
		CryptoMaterial:     doc.CryptoMaterialItems(),
		FreshnessExpiresAt: platformWitnessedAt.Add(provenance.MaxFreshnessAge),
	}, nil
}

// authenticateReferenceValues authenticates the document's required code and
// platform Sigstore artifacts plus the matching freshness proof for each,
// returning the authenticated code, platform values, and the earlier of their
// authenticated freshness expiration times.
func authenticateReferenceValues(doc *envelope.Document, repo string) (*provenance.Code, *provenance.PlatformEndorsements, time.Time, error) {
	appraisalTime := time.Now()
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
	codeWitnessedAt, err := provenance.AuthenticateFreshness(codeFreshnessRef.SigstoreBundle, &code.AuthenticatedArtifact, appraisalTime)
	if err != nil {
		return nil, nil, time.Time{}, fmt.Errorf("verifying code freshness: %w", err)
	}

	endorsements, platformWitnessedAt, err := authenticatePlatformReferenceValues(doc, appraisalTime)
	if err != nil {
		return nil, nil, time.Time{}, err
	}

	return code, endorsements, freshnessExpiration(codeWitnessedAt, platformWitnessedAt), nil
}

// authenticatePlatformReferenceValues authenticates the document's platform
// endorsement artifact and its freshness proof. It is the half of reference
// verification that remains mandatory when the caller pins the code
// measurement.
func authenticatePlatformReferenceValues(doc *envelope.Document, appraisalTime time.Time) (*provenance.PlatformEndorsements, time.Time, error) {
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
	platformWitnessedAt, err := provenance.AuthenticateFreshness(freshnessRef.SigstoreBundle, &endorsements.AuthenticatedArtifact, appraisalTime)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("verifying platform freshness: %w", err)
	}
	return endorsements, platformWitnessedAt, nil
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
	s.verifyMu.Lock()
	defer s.verifyMu.Unlock()
	return s.verifyV3()
}

func (s *SecureClient) verifyV3() (*VerifiedDocumentV3, error) {
	nonce, err := envelope.RandomNonce()
	if err != nil {
		return nil, err
	}
	docBytes, err := envelope.Fetch(s.enclave, nonce)
	if err != nil {
		return nil, fmt.Errorf("fetching attestation document: %w", err)
	}

	var verified *VerifiedDocumentV3
	if s.pin != nil {
		verified, err = VerifyDocumentV3Pinned(docBytes, nonce, s.pin)
	} else {
		verified, err = VerifyDocumentV3(docBytes, nonce, s.repo)
	}
	if err != nil {
		return nil, err
	}

	// Recover the transport keys bound into the verified CPU report. The
	// selected transport enforces its key before sending the first request.
	tlsFP, hpkeKey, err := verified.transportKeys()
	if err != nil {
		return nil, fmt.Errorf("binding: %w", err)
	}
	// Fingerprints mirror the legacy flow for consumers that display or
	// compare them. TDX fingerprints incorporate the platform registers,
	// which in v3 come from the verified quote itself (their values were
	// already appraised against the endorsed platform measurements).
	var hw *measurement.HardwareMeasurement
	if verified.EnclaveMeasurement.Type == measurement.TdxGuestV2 && len(verified.EnclaveMeasurement.Registers) >= 2 {
		hw = &measurement.HardwareMeasurement{
			MRTD:  verified.EnclaveMeasurement.Registers[0],
			RTMR0: verified.EnclaveMeasurement.Registers[1],
		}
	}
	codeFingerprint, err := measurement.Fingerprint(verified.CodeMeasurement, hw, verified.EnclaveMeasurement.Type)
	if err != nil {
		return nil, fmt.Errorf("measurements: failed to compute code fingerprint: %w", err)
	}
	enclaveFingerprint, err := measurement.Fingerprint(verified.EnclaveMeasurement, hw, verified.EnclaveMeasurement.Type)
	if err != nil {
		return nil, fmt.Errorf("measurements: failed to compute enclave fingerprint: %w", err)
	}

	s.setVerifiedState(&GroundTruth{
		ConfigRepo:          s.repo,
		EnclaveHost:         s.enclave,
		ReleaseTag:          verified.CodeTag,
		TLSPublicKey:        tlsFP,
		HPKEPublicKey:       hpkeKey,
		Digest:              verified.CodeDigest,
		CodeMeasurement:     verified.CodeMeasurement,
		EnclaveMeasurement:  verified.EnclaveMeasurement,
		HardwareMeasurement: hw,
		CodeFingerprint:     codeFingerprint,
		EnclaveFingerprint:  enclaveFingerprint,
		Verifier:            currentVerifierIdentity(),
		VerifiedAt:          verificationTime().UTC().Format(time.RFC3339Nano),
	})
	return verified, nil
}

// Verify attests the enclave with the v3 single-request flow and stores the
// resulting ground truth in the client.
func (s *SecureClient) Verify() (*GroundTruth, error) {
	s.verifyMu.Lock()
	defer s.verifyMu.Unlock()
	if _, err := s.verifyV3(); err != nil {
		return nil, err
	}
	return s.GroundTruth(), nil
}
