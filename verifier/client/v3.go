package client

import (
	"fmt"

	"github.com/tinfoilsh/tinfoil-go/verifier/attestation"
	"github.com/tinfoilsh/tinfoil-go/verifier/sigstore"
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
	// CodeDigest is the verified code artifact digest from the sigstore-code entry.
	CodeDigest string `json:"code_digest"`
	// CodeMeasurement and EnclaveMeasurement passed the equality comparison.
	CodeMeasurement    *attestation.Measurement `json:"code_measurement"`
	EnclaveMeasurement *attestation.Measurement `json:"enclave_measurement"`
	// CryptoMaterial holds the endorsed key items (hash-bound into the quote).
	CryptoMaterial []attestation.CryptoMaterialItem `json:"crypto_material"`
}

// TLSPublicKeyFP returns the endorsed TLS key fingerprint (the id=tls
// crypto_material entry), or an error if the document does not endorse one.
func (v *VerifiedDocumentV3) TLSPublicKeyFP() (string, error) {
	return v.cryptoMaterialData(attestation.CryptoMaterialIDTLS, attestation.KeySPKIFPSHA256V1Format)
}

// HPKEPublicKey returns the endorsed HPKE public key (the id=hpke
// crypto_material entry), or an error if the document does not endorse one.
func (v *VerifiedDocumentV3) HPKEPublicKey() (string, error) {
	return v.cryptoMaterialData(attestation.CryptoMaterialIDHPKE, attestation.KeyX25519HPKEV1Format)
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
//  2. Reference values: the sigstore-code and sigstore-platform collateral
//     entries are verified against the Sigstore trust root and the pinned
//     Tinfoil workflow identities, recovering the code measurement and the
//     platform-endorsements artifact. Both entries are required.
//  3. CPU evidence: quote signature chain against pinned vendor roots,
//     REPORT_DATA binding, platform identity endorsement (machines-map
//     lookup), and the endorsed appraisal policy.
//  4. The code measurement is compared against the enclave measurement.
//
// repo is the code repository the caller trusts (pins the sigstore-code
// signing identity); the repo named inside the document is not trusted.
// Channel binding (TLS fingerprint / HPKE key) is the caller's
// responsibility, using the returned endorsed crypto material.
func VerifyDocumentV3(sigstoreClient *sigstore.Client, docBytes, nonce []byte, repo string) (*VerifiedDocumentV3, error) {
	doc, expectedReportData, err := attestation.VerifyEnvelopeV3(docBytes, nonce)
	if err != nil {
		return nil, fmt.Errorf("envelope: %w", err)
	}

	// Reference values are verified before the CPU evidence because
	// endorsement enforcement needs the platform artifact.
	codeRef, found, err := doc.ReferenceValuesCollateral(attestation.CollateralSigstoreCodeV1Format)
	if err != nil {
		return nil, fmt.Errorf("reference values: %w", err)
	}
	if !found {
		return nil, fmt.Errorf("reference values: document carries no sigstore-code collateral entry")
	}
	codeMeasurement, err := sigstoreClient.VerifyAttestation(codeRef.SigstoreBundle, repo, codeRef.Digest)
	if err != nil {
		return nil, fmt.Errorf("reference values: verifying code measurement: %w", err)
	}

	platformRef, found, err := doc.ReferenceValuesCollateral(attestation.CollateralSigstorePlatformV1Format)
	if err != nil {
		return nil, fmt.Errorf("reference values: %w", err)
	}
	if !found {
		return nil, fmt.Errorf("reference values: document carries no sigstore-platform collateral entry")
	}
	endorsements, err := sigstoreClient.VerifyPlatformEndorsements(platformRef.SigstoreBundle, platformRef.Digest)
	if err != nil {
		return nil, fmt.Errorf("reference values: verifying platform endorsements: %w", err)
	}

	evidence, err := attestation.VerifyCPUEvidenceV3(doc, expectedReportData, endorsements)
	if err != nil {
		return nil, fmt.Errorf("cpu evidence: %w", err)
	}

	if err := codeMeasurement.Equals(evidence.Measurement); err != nil {
		return nil, fmt.Errorf("measurements: %w", err)
	}

	return &VerifiedDocumentV3{
		Platform:           evidence.Platform,
		PlatformIdentity:   evidence.PlatformIdentity,
		PolicyName:         evidence.PolicyName,
		CodeDigest:         codeRef.Digest,
		CodeMeasurement:    codeMeasurement,
		EnclaveMeasurement: evidence.Measurement,
		CryptoMaterial:     doc.CryptoMaterialItems(),
	}, nil
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
	if s.sigstoreClient == nil {
		var err error
		s.sigstoreClient, err = getSigstoreClient(nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create sigstore client: %v", err)
		}
	}
	sigstoreClient := s.sigstoreClient

	nonce, err := attestation.RandomNonce()
	if err != nil {
		return nil, err
	}
	docBytes, err := attestation.FetchV3(s.enclave, nonce)
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
	hpkeKey, _ := verified.HPKEPublicKey()
	if err := enclaveValidPubKey(s.enclave, &attestation.Verification{TLSPublicKeyFP: tlsFP}); err != nil {
		return nil, fmt.Errorf("binding: %v", err)
	}

	s.groundTruth = &GroundTruth{
		EnclaveHost:        s.enclave,
		TLSPublicKey:       tlsFP,
		HPKEPublicKey:      hpkeKey,
		Digest:             verified.CodeDigest,
		CodeMeasurement:    verified.CodeMeasurement,
		EnclaveMeasurement: verified.EnclaveMeasurement,
	}
	return verified, nil
}
