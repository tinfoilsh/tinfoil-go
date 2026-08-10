package client

import (
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

	code, codeTag, codeDigest, endorsements, err := authenticateReferenceValues(doc, repo)
	if err != nil {
		return nil, fmt.Errorf("reference values: %w", err)
	}

	_, authenticated, err := quote.Verify(doc, endorsements.Artifact, code.Measurement, code.Shape, expectedReportData)
	if err != nil {
		return nil, fmt.Errorf("cpu evidence: %w", err)
	}

	return &VerifiedDocumentV3{
		CodeDigest:         codeDigest,
		CodeTag:            codeTag,
		CodeMeasurement:    code.Measurement,
		EnclaveMeasurement: authenticated.Measurement,
		CryptoMaterial:     doc.CryptoMaterialItems(),
	}, nil
}

// authenticateReferenceValues authenticates the document's required code and
// platform Sigstore artifacts plus the matching freshness proof for each,
// returning the verified code provenance, its digest, and the policy artifact.
func authenticateReferenceValues(doc *envelope.Document, repo string) (*provenance.Code, string, string, *provenance.PlatformEndorsements, error) {
	codeRef, err := doc.ReferenceValuesCollateral(envelope.CollateralSigstoreCodeV1Format)
	if err != nil {
		return nil, "", "", nil, err
	}
	code, err := provenance.AuthenticateCode(codeRef.SigstoreBundle, repo, codeRef.Tag, codeRef.Digest)
	if err != nil {
		return nil, "", "", nil, fmt.Errorf("verifying code measurement: %w", err)
	}
	codeFreshnessRef, err := doc.FreshnessCollateral(envelope.FreshnessCollateralIDCode)
	if err != nil {
		return nil, "", "", nil, err
	}
	if _, err := provenance.AuthenticateFreshness(codeFreshnessRef.SigstoreBundle, &code.AuthenticatedArtifact, time.Now()); err != nil {
		return nil, "", "", nil, fmt.Errorf("verifying code freshness: %w", err)
	}

	platformRef, err := doc.ReferenceValuesCollateral(envelope.CollateralSigstorePlatformV1Format)
	if err != nil {
		return nil, "", "", nil, err
	}
	endorsements, err := provenance.AuthenticatePlatformEndorsements(platformRef.SigstoreBundle, platformRef.Repo, platformRef.Tag, platformRef.Digest)
	if err != nil {
		return nil, "", "", nil, fmt.Errorf("verifying platform endorsements: %w", err)
	}
	freshnessRef, err := doc.FreshnessCollateral(envelope.FreshnessCollateralIDPlatform)
	if err != nil {
		return nil, "", "", nil, err
	}
	if _, err := provenance.AuthenticateFreshness(freshnessRef.SigstoreBundle, &endorsements.AuthenticatedArtifact, time.Now()); err != nil {
		return nil, "", "", nil, fmt.Errorf("verifying platform freshness: %w", err)
	}

	return code, code.Tag, code.Digest, endorsements, nil
}

// VerifyV3 runs the single-request v3 flow against the client's enclave:
// generate a fresh nonce, fetch the document (evidence + collateral) in one
// request, verify it, and bind the TLS channel to the endorsed key. On
// success the client's ground truth is updated so HTTPClient enforces the
// endorsed TLS key on every subsequent connection.
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

	verified, err := VerifyDocumentV3(docBytes, nonce, s.repo)
	if err != nil {
		return nil, err
	}

	// Channel binding: the live TLS key must equal the endorsed fingerprint.
	// Enforced again per-connection by TLSBoundRoundTripper.
	tlsFP, err := verified.TLSPublicKeyFP()
	if err != nil {
		return nil, fmt.Errorf("binding: %w", err)
	}
	hpkeKey, err := verified.HPKEPublicKey()
	if err != nil {
		return nil, fmt.Errorf("binding: %w", err)
	}
	if err := enclaveValidPubKey(s.enclave, tlsFP); err != nil {
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
