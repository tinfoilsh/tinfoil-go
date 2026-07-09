package attestation

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"regexp"

	"github.com/tinfoilsh/tinfoil-go/verifier/util"
)

// Attestation document v3 (predicate https://tinfoil.sh/predicate/attestation/v3).
//
// The document is flat: a challenge, CPU evidence, two endorsed sections
// (crypto_material, device_evidence), and an array of collateral entries.
// The endorsed sections are hash-bound into the CPU quote's REPORT_DATA:
//
//	crypto_material_hash = SHA-256(crypto_material section bytes as transmitted)
//	device_evidence_hash = SHA-256(device_evidence section bytes as transmitted)
//	REPORT_DATA[0:32]    = SHA-256(nonce || crypto_material_hash || device_evidence_hash)
//	REPORT_DATA[32:64]   = zeros
//
// Endorsed-section hashes are computed over the exact bytes of the JSON
// member value as transmitted; verifiers must never re-serialize them.

// Format registry (v3).
const (
	// AttestationV3Format identifies the v3 attestation document.
	AttestationV3Format = "https://tinfoil.sh/predicate/attestation/v3"

	// ReportDataV1Algorithm identifies the REPORT_DATA derivation above.
	ReportDataV1Algorithm = "https://tinfoil.sh/report-data/v1"

	// CryptoMaterialV1Format is the crypto_material section envelope.
	CryptoMaterialV1Format = "https://tinfoil.sh/crypto-material/v1"
	// DeviceEvidenceV1Format is the device_evidence section envelope.
	DeviceEvidenceV1Format = "https://tinfoil.sh/device-evidence/v1"

	// SEVSNPReportV1Format is a raw 1184-byte SEV-SNP report, base64.
	SEVSNPReportV1Format = "https://tinfoil.sh/format/sev-snp-report/v1"
	// TDXQuoteV1Format is a raw TDX Quote v4, base64.
	TDXQuoteV1Format = "https://tinfoil.sh/format/tdx-quote/v1"
	// NvidiaGPUEvidenceV1Format is an NVIDIA GPU evidence payload.
	NvidiaGPUEvidenceV1Format = "https://tinfoil.sh/format/nvidia-gpu-evidence/v1"

	// KeySPKIFPSHA256V1Format is a 32-byte SHA-256 of the DER-encoded
	// SubjectPublicKeyInfo (RFC 5280), the standard pinning computation.
	KeySPKIFPSHA256V1Format = "https://tinfoil.sh/key/spki-fp-sha256/v1"
	// KeyX25519HPKEV1Format is a raw 32-byte X25519 public key (RFC 7748)
	// used for HPKE (RFC 9180).
	KeyX25519HPKEV1Format = "https://tinfoil.sh/key/x25519-hpke/v1"

	// CollateralAMDVCEKV1Format carries {vcek_der_base64, cert_chain_pem}.
	CollateralAMDVCEKV1Format = "https://tinfoil.sh/collateral/amd-vcek/v1"
	// CollateralIntelPCSV1Format carries captured Intel PCS responses
	// (TCB info, QE identity, CRLs) for offline TDX quote verification.
	CollateralIntelPCSV1Format = "https://tinfoil.sh/collateral/intel-pcs/v1"
	// CollateralNvidiaGPUV1Format carries NVIDIA cert chains / RIM material.
	CollateralNvidiaGPUV1Format = "https://tinfoil.sh/collateral/nvidia-gpu/v1"
	// CollateralSigstoreCodeV1Format carries the code-provenance Sigstore
	// bundle {repo, tag, digest, sigstore_bundle}.
	CollateralSigstoreCodeV1Format = "https://tinfoil.sh/collateral/sigstore-code/v1"
	// CollateralSigstorePlatformV1Format carries the platform-endorsements
	// Sigstore bundle {repo, tag, digest, sigstore_bundle}.
	CollateralSigstorePlatformV1Format = "https://tinfoil.sh/collateral/sigstore-platform/v1"
)

// Collateral roles (RATS, RFC 9334).
const (
	// RoleEndorsement labels hardware-vendor material used to
	// cryptographically verify evidence (e.g. AMD VCEK chains, Intel PCS).
	RoleEndorsement = "endorsement"
	// RoleReferenceValues labels Tinfoil-signed expectations used to
	// appraise verified evidence.
	RoleReferenceValues = "reference-values"
)

// Conventional identifiers.
const (
	// CryptoMaterialIDTLS is the conventional id of the TLS key fingerprint.
	CryptoMaterialIDTLS = "tls"
	// CryptoMaterialIDHPKE is the conventional id of the HPKE public key.
	CryptoMaterialIDHPKE = "hpke"
	// SubjectCPU is the reserved collateral subject id for the CPU quote.
	SubjectCPU = "cpu"
)

// NonceSize is the required challenge nonce size in bytes.
const NonceSize = 32

// DocumentV3 is the wire shape of a v3 attestation document. The endorsed
// sections are kept as raw bytes: their hashes are computed over the exact
// transmitted bytes, never a re-serialization.
type DocumentV3 struct {
	Format         string            `json:"format"`
	Challenge      ChallengeV3       `json:"challenge"`
	CPUEvidence    CPUEvidenceV3     `json:"cpu_evidence"`
	CryptoMaterial json.RawMessage   `json:"crypto_material"`
	DeviceEvidence json.RawMessage   `json:"device_evidence"`
	Collateral     []CollateralEntry `json:"collateral"`

	cryptoMaterial *CryptoMaterialSection
	deviceEvidence *DeviceEvidenceSection
}

// ChallengeV3 binds the document to a verifier-chosen nonce.
type ChallengeV3 struct {
	Nonce               string `json:"nonce"`
	ReportData          string `json:"report_data"`
	ReportDataAlgorithm string `json:"report_data_algorithm"`
}

// CPUEvidenceV3 is the hardware quote and the endorsed-section hashes it binds.
type CPUEvidenceV3 struct {
	Format       string           `json:"format"`
	ReportBase64 string           `json:"report_base64"`
	Endorsed     EndorsedHashesV3 `json:"endorsed"`
}

// EndorsedHashesV3 are the SHA-256 hashes of the two endorsed sections,
// bound into the quote's REPORT_DATA.
type EndorsedHashesV3 struct {
	CryptoMaterialHash string `json:"crypto_material_hash"`
	DeviceEvidenceHash string `json:"device_evidence_hash"`
}

// CryptoMaterialSection is the endorsed crypto_material section envelope.
type CryptoMaterialSection struct {
	Format string               `json:"format"`
	Items  []CryptoMaterialItem `json:"items"`
}

// CryptoMaterialItem is one endorsed key: the item format URI fully
// determines how Data (lowercase hex) is interpreted.
type CryptoMaterialItem struct {
	ID     string `json:"id"`
	Format string `json:"format"`
	Data   string `json:"data"`
}

// DeviceEvidenceSection is the endorsed device_evidence section envelope.
// Empty device evidence is Items: [] — the section is always present.
type DeviceEvidenceSection struct {
	Format string               `json:"format"`
	Items  []DeviceEvidenceItem `json:"items"`
}

// DeviceEvidenceItem is one device's evidence; the item format URI versions
// the Evidence payload.
type DeviceEvidenceItem struct {
	ID       string          `json:"id"`
	Kind     string          `json:"kind"`
	Vendor   string          `json:"vendor"`
	Format   string          `json:"format"`
	Evidence json.RawMessage `json:"evidence"`
}

// CollateralEntry is one self-describing collateral record. Collateral is
// unendorsed transport: every entry is authenticated by its own signature
// chain during verification, so a tampered entry can only cause rejection.
type CollateralEntry struct {
	ID       string          `json:"id"`
	Role     string          `json:"role"`
	Format   string          `json:"format"`
	Subjects []string        `json:"subjects,omitempty"`
	Data     json.RawMessage `json:"data"`
}

// AMDVCEKCollateral is the data of a CollateralAMDVCEKV1Format entry.
type AMDVCEKCollateral struct {
	VCEKDERBase64 string `json:"vcek_der_base64"`
	CertChainPEM  string `json:"cert_chain_pem"`
}

// IntelPCSCollateral is the data of a CollateralIntelPCSV1Format entry:
// Intel PCS responses captured verbatim so a verifier can replay them
// instead of fetching. Headers are included because Intel delivers issuer
// chains in response headers.
type IntelPCSCollateral struct {
	Responses []PCSResponse `json:"responses"`
}

// PCSResponse is one captured Intel PCS response.
type PCSResponse struct {
	URL        string              `json:"url"`
	Headers    map[string][]string `json:"headers"`
	BodyBase64 string              `json:"body_base64"`
}

// SigstoreCollateral is the data of a sigstore-code or sigstore-platform
// reference-values entry. Repo and Tag are informational; trust comes from
// verifying SigstoreBundle against the expected signing identity and Digest.
type SigstoreCollateral struct {
	Repo           string          `json:"repo"`
	Tag            string          `json:"tag"`
	Digest         string          `json:"digest"`
	SigstoreBundle json.RawMessage `json:"sigstore_bundle"`
}

var lowerHexV3 = regexp.MustCompile(`^[0-9a-f]*$`)

// decodeLowerHex decodes a required lowercase hex field of an exact byte length.
func decodeLowerHex(name, value string, wantLen int) ([]byte, error) {
	if !lowerHexV3.MatchString(value) {
		return nil, fmt.Errorf("%s is not lowercase hex", name)
	}
	b, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("%s is not hex: %w", name, err)
	}
	if len(b) != wantLen {
		return nil, fmt.Errorf("%s must be %d bytes, got %d", name, wantLen, len(b))
	}
	return b, nil
}

// ComputeReportDataV3 derives the 64-byte REPORT_DATA per the
// https://tinfoil.sh/report-data/v1 algorithm. All inputs are exactly 32
// bytes; the concatenation is fixed-order and fixed-length.
func ComputeReportDataV3(nonce, cryptoMaterialHash, deviceEvidenceHash []byte) ([64]byte, error) {
	var out [64]byte
	if len(nonce) != 32 || len(cryptoMaterialHash) != 32 || len(deviceEvidenceHash) != 32 {
		return out, fmt.Errorf("report data inputs must be 32 bytes each (got %d, %d, %d)",
			len(nonce), len(cryptoMaterialHash), len(deviceEvidenceHash))
	}
	h := sha256.New()
	h.Write(nonce)
	h.Write(cryptoMaterialHash)
	h.Write(deviceEvidenceHash)
	copy(out[:32], h.Sum(nil))
	return out, nil
}

// RandomNonce generates a cryptographically random 32-byte challenge nonce.
func RandomNonce() ([]byte, error) {
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}
	return nonce, nil
}

// ParseDocumentV3 strictly parses a v3 attestation document from its
// transmitted bytes. Unknown members anywhere in the fixed schema are
// rejected, all hex is validated lowercase, and duplicate item ids within
// an endorsed section are rejected. The endorsed sections are retained as
// raw bytes for hashing.
func ParseDocumentV3(docBytes []byte) (*DocumentV3, error) {
	dec := json.NewDecoder(bytes.NewReader(docBytes))
	dec.DisallowUnknownFields()
	var doc DocumentV3
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("parsing attestation document: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("trailing data after attestation document")
	}

	if doc.Format != AttestationV3Format {
		return nil, fmt.Errorf("%w: unsupported document format %q", ErrFormatMismatch, doc.Format)
	}
	if doc.Challenge.ReportDataAlgorithm != ReportDataV1Algorithm {
		return nil, fmt.Errorf("unsupported report_data_algorithm %q", doc.Challenge.ReportDataAlgorithm)
	}
	if _, err := decodeLowerHex("challenge.nonce", doc.Challenge.Nonce, NonceSize); err != nil {
		return nil, err
	}
	if _, err := decodeLowerHex("challenge.report_data", doc.Challenge.ReportData, 64); err != nil {
		return nil, err
	}
	if _, err := decodeLowerHex("cpu_evidence.endorsed.crypto_material_hash", doc.CPUEvidence.Endorsed.CryptoMaterialHash, 32); err != nil {
		return nil, err
	}
	if _, err := decodeLowerHex("cpu_evidence.endorsed.device_evidence_hash", doc.CPUEvidence.Endorsed.DeviceEvidenceHash, 32); err != nil {
		return nil, err
	}
	if doc.CPUEvidence.Format == "" || doc.CPUEvidence.ReportBase64 == "" {
		return nil, fmt.Errorf("cpu_evidence is incomplete")
	}
	if len(doc.CryptoMaterial) == 0 {
		return nil, fmt.Errorf("crypto_material section is missing")
	}
	if len(doc.DeviceEvidence) == 0 {
		return nil, fmt.Errorf("device_evidence section is missing")
	}

	var cm CryptoMaterialSection
	if err := strictUnmarshal(doc.CryptoMaterial, &cm); err != nil {
		return nil, fmt.Errorf("parsing crypto_material: %w", err)
	}
	if cm.Format != CryptoMaterialV1Format {
		return nil, fmt.Errorf("unsupported crypto_material section format %q", cm.Format)
	}
	if cm.Items == nil {
		return nil, fmt.Errorf("crypto_material.items is missing")
	}
	seen := make(map[string]bool, len(cm.Items))
	for _, item := range cm.Items {
		if item.ID == "" || item.Format == "" {
			return nil, fmt.Errorf("crypto_material item is incomplete")
		}
		if seen[item.ID] {
			return nil, fmt.Errorf("duplicate crypto_material item id %q", item.ID)
		}
		seen[item.ID] = true
		switch item.Format {
		case KeySPKIFPSHA256V1Format, KeyX25519HPKEV1Format:
			// Known key formats are exactly 32 bytes; reject short, empty,
			// or odd-length material before callers trust it.
			if _, err := decodeLowerHex(fmt.Sprintf("crypto_material item %q data", item.ID), item.Data, 32); err != nil {
				return nil, err
			}
		default:
			if !lowerHexV3.MatchString(item.Data) {
				return nil, fmt.Errorf("crypto_material item %q data is not lowercase hex", item.ID)
			}
		}
	}

	var de DeviceEvidenceSection
	if err := strictUnmarshal(doc.DeviceEvidence, &de); err != nil {
		return nil, fmt.Errorf("parsing device_evidence: %w", err)
	}
	if de.Format != DeviceEvidenceV1Format {
		return nil, fmt.Errorf("unsupported device_evidence section format %q", de.Format)
	}
	if de.Items == nil {
		return nil, fmt.Errorf("device_evidence.items is missing")
	}
	seen = make(map[string]bool, len(de.Items))
	for _, item := range de.Items {
		if item.ID == "" {
			return nil, fmt.Errorf("device_evidence item has no id")
		}
		if seen[item.ID] {
			return nil, fmt.Errorf("duplicate device_evidence item id %q", item.ID)
		}
		seen[item.ID] = true
	}

	for i, entry := range doc.Collateral {
		if entry.ID == "" || entry.Format == "" {
			return nil, fmt.Errorf("collateral entry %d is incomplete", i)
		}
		if entry.Role != RoleEndorsement && entry.Role != RoleReferenceValues {
			return nil, fmt.Errorf("collateral entry %q has unknown role %q", entry.ID, entry.Role)
		}
	}

	doc.cryptoMaterial = &cm
	doc.deviceEvidence = &de
	return &doc, nil
}

// CryptoMaterialItems returns the parsed crypto_material items.
func (d *DocumentV3) CryptoMaterialItems() []CryptoMaterialItem {
	if d.cryptoMaterial == nil {
		return nil
	}
	return d.cryptoMaterial.Items
}

// DeviceEvidenceItems returns the parsed device_evidence items.
func (d *DocumentV3) DeviceEvidenceItems() []DeviceEvidenceItem {
	if d.deviceEvidence == nil {
		return nil
	}
	return d.deviceEvidence.Items
}

// CryptoMaterialItem returns the crypto_material item with the given id.
func (d *DocumentV3) CryptoMaterialItem(id string) (*CryptoMaterialItem, bool) {
	for i := range d.CryptoMaterialItems() {
		if d.cryptoMaterial.Items[i].ID == id {
			return &d.cryptoMaterial.Items[i], true
		}
	}
	return nil, false
}

// VerifyEnvelopeV3 parses a v3 document from its transmitted bytes and
// performs the challenge and hash-binding checks: the nonce matches the
// verifier's expected nonce, the endorsed-section hashes recomputed over the
// transported bytes match cpu_evidence.endorsed, and REPORT_DATA recomputed
// from them matches challenge.report_data. It returns the parsed document
// and the expected REPORT_DATA the CPU quote must bind.
//
// This authenticates nothing by itself: callers must verify the CPU evidence
// (which proves the hardware bound this REPORT_DATA) before trusting any
// part of the document.
func VerifyEnvelopeV3(docBytes []byte, expectedNonce []byte) (*DocumentV3, [64]byte, error) {
	var zero [64]byte
	if len(expectedNonce) != NonceSize {
		return nil, zero, fmt.Errorf("expected nonce must be %d bytes, got %d", NonceSize, len(expectedNonce))
	}
	doc, err := ParseDocumentV3(docBytes)
	if err != nil {
		return nil, zero, err
	}
	if doc.Challenge.Nonce != hex.EncodeToString(expectedNonce) {
		return nil, zero, fmt.Errorf("challenge nonce does not match the expected nonce")
	}

	cryptoHash := sha256.Sum256(doc.CryptoMaterial)
	deviceHash := sha256.Sum256(doc.DeviceEvidence)
	if hex.EncodeToString(cryptoHash[:]) != doc.CPUEvidence.Endorsed.CryptoMaterialHash {
		return nil, zero, fmt.Errorf("crypto_material hash does not match cpu_evidence.endorsed.crypto_material_hash")
	}
	if hex.EncodeToString(deviceHash[:]) != doc.CPUEvidence.Endorsed.DeviceEvidenceHash {
		return nil, zero, fmt.Errorf("device_evidence hash does not match cpu_evidence.endorsed.device_evidence_hash")
	}

	reportData, err := ComputeReportDataV3(expectedNonce, cryptoHash[:], deviceHash[:])
	if err != nil {
		return nil, zero, err
	}
	if hex.EncodeToString(reportData[:]) != doc.Challenge.ReportData {
		return nil, zero, fmt.Errorf("challenge report_data does not match the recomputed value")
	}
	return doc, reportData, nil
}

// FetchV3 retrieves a v3 attestation document from an enclave host using a
// fresh challenge nonce. It returns the raw response bytes: verification
// hashes the transported bytes, so the document must not be re-serialized
// between fetch and verify.
func FetchV3(host string, nonce []byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		return nil, fmt.Errorf("nonce must be %d bytes, got %d", NonceSize, len(nonce))
	}
	u := url.URL{
		Scheme:   "https",
		Host:     host,
		Path:     attestationEndpoint,
		RawQuery: "nonce=" + hex.EncodeToString(nonce),
	}
	body, _, err := util.Get(u.String())
	if err != nil {
		return nil, err
	}
	return body, nil
}

func strictUnmarshal(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("trailing data")
	}
	return nil
}
