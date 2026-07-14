package client

import (
	"fmt"

	"github.com/tinfoilsh/tinfoil-go/verifier/envelope"
	"github.com/tinfoilsh/tinfoil-go/verifier/measurement"
	"github.com/tinfoilsh/tinfoil-go/verifier/policy"
	"github.com/tinfoilsh/tinfoil-go/verifier/provenance"
	"github.com/tinfoilsh/tinfoil-go/verifier/quote"
)

// VerifiedDocumentV3 is the set of verified facts a v3 attestation document
// proves.
type VerifiedDocumentV3 struct {
	// Platform is "sev-snp" or "tdx".
	Platform string `json:"platform"`
	// PlatformIdentity is the endorsed machine identifier (lowercase hex).
	PlatformIdentity string `json:"platform_identity"`
	// PolicyName is the matched appraisal policy in the platform-endorsements artifact.
	PolicyName string `json:"policy_name"`
	// PlatformMeasurementName names the endorsed TDX platform configuration
	// the quote resolved to; empty for SEV-SNP.
	PlatformMeasurementName string `json:"platform_measurement_name,omitempty"`
	// CodeDigest is the verified code artifact digest from the sigstore-code entry.
	CodeDigest string `json:"code_digest"`
	// CodeMeasurement is the verified code measurement; EnclaveMeasurement
	// carries the quote's authenticated registers, which validation proved
	// match it.
	CodeMeasurement    *measurement.Measurement `json:"code_measurement"`
	EnclaveMeasurement *measurement.Measurement `json:"enclave_measurement"`
	// CryptoMaterial holds the endorsed key items (hash-bound into the quote).
	CryptoMaterial []envelope.CryptoMaterialItem `json:"crypto_material"`
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
//  1. Envelope: format, nonce equality, endorsed-section hash recomputation,
//     REPORT_DATA recomputation.
//  2. Reference values: the sigstore-code and sigstore-platform entries
//     (both required) are verified against the pinned signing identities,
//     recovering the code measurement, its declared VM shape, and the
//     policy artifact.
//  3. CPU quote: authenticate against the pinned vendor roots, assemble
//     the complete policy from the verified reference values, validate in
//     one call.
//
// repo is the code repository the caller trusts (pins the sigstore-code
// signing identity); the repo named inside the document is not trusted.
// Channel binding (TLS fingerprint / HPKE key) is the caller's
// responsibility, using the returned endorsed crypto material.
func VerifyDocumentV3(sigstoreClient *provenance.Client, docBytes, nonce []byte, repo string) (*VerifiedDocumentV3, error) {
	doc, expectedReportData, err := envelope.Verify(docBytes, nonce)
	if err != nil {
		return nil, fmt.Errorf("envelope: %w", err)
	}

	code, codeDigest, endorsements, err := verifyReferenceValues(sigstoreClient, doc, repo)
	if err != nil {
		return nil, fmt.Errorf("reference values: %w", err)
	}

	assembled, authenticated, err := quote.Verify(doc, endorsements, code.Measurement, code.Shape, expectedReportData)
	if err != nil {
		return nil, fmt.Errorf("cpu evidence: %w", err)
	}

	return &VerifiedDocumentV3{
		Platform:                authenticated.Platform,
		PlatformIdentity:        authenticated.Identity,
		PolicyName:              assembled.PolicyName,
		PlatformMeasurementName: assembled.PlatformMeasurementName,
		CodeDigest:              codeDigest,
		CodeMeasurement:         code.Measurement,
		EnclaveMeasurement:      authenticated.Measurement,
		CryptoMaterial:          doc.CryptoMaterialItems(),
	}, nil
}

// verifyReferenceValues verifies the document's sigstore-code and
// sigstore-platform collateral entries, returning the verified code
// provenance, the code artifact digest, and the platform-endorsements
// artifact. Both entries are required.
func verifyReferenceValues(sigstoreClient *provenance.Client, doc *envelope.Document, repo string) (*provenance.Code, string, *policy.Artifact, error) {
	codeRef, err := doc.ReferenceValuesCollateral(envelope.CollateralSigstoreCodeV1Format)
	if err != nil {
		return nil, "", nil, err
	}
	code, err := sigstoreClient.VerifyCode(codeRef.SigstoreBundle, repo, codeRef.Digest)
	if err != nil {
		return nil, "", nil, fmt.Errorf("verifying code measurement: %w", err)
	}

	platformRef, err := doc.ReferenceValuesCollateral(envelope.CollateralSigstorePlatformV1Format)
	if err != nil {
		return nil, "", nil, err
	}
	endorsements, err := sigstoreClient.VerifyPlatformEndorsements(platformRef.SigstoreBundle, platformRef.Digest)
	if err != nil {
		return nil, "", nil, fmt.Errorf("verifying platform endorsements: %w", err)
	}

	return code, codeRef.Digest, endorsements, nil
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
	sigstoreClient, err := s.getSigstoreClient()
	if err != nil {
		return nil, err
	}

	nonce, err := envelope.RandomNonce()
	if err != nil {
		return nil, err
	}
	docBytes, err := envelope.Fetch(s.enclave, nonce)
	if err != nil {
		return nil, fmt.Errorf("fetching attestation document: %w", err)
	}

	verified, err := VerifyDocumentV3(sigstoreClient, docBytes, nonce, s.repo)
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

	s.groundTruth = &GroundTruth{
		EnclaveHost:         s.enclave,
		TLSPublicKey:        tlsFP,
		HPKEPublicKey:       hpkeKey,
		Digest:              verified.CodeDigest,
		CodeMeasurement:     verified.CodeMeasurement,
		EnclaveMeasurement:  verified.EnclaveMeasurement,
		HardwareMeasurement: hw,
		CodeFingerprint:     codeFingerprint,
		EnclaveFingerprint:  enclaveFingerprint,
	}
	return verified, nil
}
