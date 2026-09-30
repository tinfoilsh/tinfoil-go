// Package document defines the v3 attestation document wire format and its
// strict parsing, which checks the challenge against the caller's nonce.
// Parsing authenticates nothing by itself: the CPU quote must prove the
// hardware bound the recomputed REPORT_DATA before any part of the document
// is trusted.
package document

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"slices"

	"github.com/tinfoilsh/tinfoil-go/verifier/internal/errs"
)

// Attestation document v3 (predicate https://tinfoil.sh/predicate/attestation/v3).
//
// The document is flat: a challenge, CPU evidence, two endorsed sections
// (crypto_material, device_evidence), and an array of collateral entries.
// The endorsed sections are hash-bound into the CPU quote's REPORT_DATA:
//
//	crypto_material_hash = SHA-256(base64-decoded crypto_material JSON bytes)
//	device_evidence_hash = SHA-256(base64-decoded device_evidence JSON bytes)
//	REPORT_DATA[0:32]    = SHA-256(ReportDataV1Algorithm || nonce || crypto_material_hash || device_evidence_hash)
//	REPORT_DATA[32:64]   = zeros
//
// Endorsed-section hashes are computed over the exact base64-decoded section
// bytes; verifiers must never re-serialize them.

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
	// KeySPKIV1Format carries a complete DER-encoded SubjectPublicKeyInfo as
	// lowercase hex. Consumers validate the key algorithm for their protocol.
	KeySPKIV1Format = "https://tinfoil.sh/key/spki/v1"
	// KeyX25519HPKEV1Format is a raw 32-byte X25519 public key (RFC 7748)
	// used for HPKE (RFC 9180).
	KeyX25519HPKEV1Format = "https://tinfoil.sh/key/x25519-hpke/v1"

	// CollateralAMDVCEKV1Format carries {vcek_der_base64, cert_chain_pem}.
	CollateralAMDVCEKV1Format = "https://tinfoil.sh/collateral/amd-vcek/v1"
	// CollateralAMDCRLV1Format carries {crl_der_base64}: the AMD KDS CRL for
	// the product line, enabling offline VCEK revocation checking.
	CollateralAMDCRLV1Format = "https://tinfoil.sh/collateral/amd-crl/v1"
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
	// CollateralSigstoreFreshnessV1Format carries a freshness witness for a
	// Sigstore reference-values artifact.
	CollateralSigstoreFreshnessV1Format = "https://tinfoil.sh/collateral/sigstore-freshness/v1"
)

// Conventional identifiers.
const (
	// CryptoMaterialIDTLS is the conventional id of the TLS key fingerprint.
	CryptoMaterialIDTLS = "tls"
	// CryptoMaterialIDHPKE is the conventional id of the HPKE public key.
	CryptoMaterialIDHPKE = "hpke"
	// SubjectCPU is the reserved collateral subject id for the CPU quote.
	SubjectCPU = "cpu"
	// Freshness collateral IDs associate each freshness proof with the
	// Sigstore reference-values entry it refreshes.
	FreshnessCollateralIDCode     = "code-freshness"
	FreshnessCollateralIDPlatform = "platform-freshness"
)

// NonceSize is the required challenge nonce size in bytes.
const NonceSize = 32

// rawDocument is the serialized shape of a v3 attestation document. The
// endorsed sections travel base64-encoded: the builder serializes each
// section once and the encoded string carries those exact bytes, so every
// verifier recovers them with a plain base64 decode — no re-serialization, no
// canonicalization, no raw-span extraction (the same envelope discipline as
// DSSE and JWS).
type rawDocument struct {
	Format         string            `json:"format"`
	Challenge      challenge         `json:"challenge"`
	CPUEvidence    rawCPUEvidence    `json:"cpu_evidence"`
	CryptoMaterial string            `json:"crypto_material"`
	DeviceEvidence string            `json:"device_evidence"`
	Collateral     []CollateralEntry `json:"collateral"`
}

// Document is a parsed v3 attestation document. Obtain one from Parse, which
// decodes every field and checks the challenge against the caller's nonce;
// its accessors return decoded copies. Methods require a document returned by
// Parse: only ExpectedReportData accepts a nil or zero-value Document.
type Document struct {
	challenge  challenge
	endorsed   endorsedHashes
	evidence   CPUEvidence
	collateral []CollateralEntry

	cryptoMaterialBytes []byte
	deviceEvidenceBytes []byte
	cryptoMaterial      *cryptoMaterialSection
	deviceEvidence      *deviceEvidenceSection

	// bound records that bind checked the challenge against the caller's
	// nonce; reportData is the REPORT_DATA it recomputed. A zero-value
	// Document can always be declared outside this package, so bound is what
	// tells a parsed document from one that was never checked.
	bound      bool
	reportData [64]byte
}

// CPUEvidence is a document's decoded hardware evidence.
type CPUEvidence struct {
	// Format selects the platform, e.g. SEVSNPReportV1Format.
	Format string
	// Report is the raw report (SEV-SNP) or quote (TDX).
	Report []byte
}

// Clone returns a deep copy of e.
func (e CPUEvidence) Clone() CPUEvidence {
	return CPUEvidence{Format: e.Format, Report: slices.Clone(e.Report)}
}

// challenge binds the document to a verifier-chosen nonce.
type challenge struct {
	Nonce               string `json:"nonce"`
	ReportData          string `json:"report_data"`
	ReportDataAlgorithm string `json:"report_data_algorithm"`
}

func (c *challenge) parse() error {
	if c.ReportDataAlgorithm != ReportDataV1Algorithm {
		return fmt.Errorf("unsupported challenge.report_data_algorithm %q", c.ReportDataAlgorithm)
	}
	if _, err := decodeLowerHex("challenge.nonce", c.Nonce, NonceSize); err != nil {
		return err
	}
	if _, err := decodeLowerHex("challenge.report_data", c.ReportData, 64); err != nil {
		return err
	}
	return nil
}

// rawCPUEvidence is the hardware quote and the endorsed-section hashes it binds.
type rawCPUEvidence struct {
	Format       string         `json:"format"`
	ReportBase64 string         `json:"report_base64"`
	Endorsed     endorsedHashes `json:"endorsed"`
}

// parse checks the CPU evidence and returns its decoded report.
func (c *rawCPUEvidence) parse() ([]byte, error) {
	if _, err := decodeLowerHex("cpu_evidence.endorsed.crypto_material_hash", c.Endorsed.CryptoMaterialHash, 32); err != nil {
		return nil, err
	}
	if _, err := decodeLowerHex("cpu_evidence.endorsed.device_evidence_hash", c.Endorsed.DeviceEvidenceHash, 32); err != nil {
		return nil, err
	}
	if c.Format == "" || c.ReportBase64 == "" {
		return nil, fmt.Errorf("cpu_evidence is incomplete")
	}
	return decodeCanonicalBase64("cpu_evidence.report_base64", c.ReportBase64)
}

// endorsedHashes are the SHA-256 hashes of the two endorsed sections,
// bound into the quote's REPORT_DATA.
type endorsedHashes struct {
	CryptoMaterialHash string `json:"crypto_material_hash"`
	DeviceEvidenceHash string `json:"device_evidence_hash"`
}

// cryptoMaterialSection is the endorsed crypto_material section envelope.
type cryptoMaterialSection struct {
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

func parseCryptoMaterial(encoded string) (*cryptoMaterialSection, []byte, error) {
	if encoded == "" {
		return nil, nil, fmt.Errorf("crypto_material section is missing")
	}
	cryptoBytes, err := decodeCanonicalBase64("crypto_material", encoded)
	if err != nil {
		return nil, nil, err
	}

	var cm cryptoMaterialSection
	if err := json.Unmarshal(cryptoBytes, &cm, json.RejectUnknownMembers(true)); err != nil {
		return nil, nil, fmt.Errorf("parsing crypto_material: %w", err)
	}
	if cm.Format != CryptoMaterialV1Format {
		return nil, nil, fmt.Errorf("unsupported crypto_material section format %q", cm.Format)
	}
	if cm.Items == nil {
		return nil, nil, fmt.Errorf("crypto_material.items is missing")
	}
	seen := make(map[string]bool, len(cm.Items))
	for _, item := range cm.Items {
		if item.ID == "" || item.Format == "" {
			return nil, nil, fmt.Errorf("crypto_material item is incomplete")
		}
		if seen[item.ID] {
			return nil, nil, fmt.Errorf("duplicate crypto_material item id %q", item.ID)
		}
		seen[item.ID] = true
		switch item.Format {
		case KeySPKIFPSHA256V1Format, KeyX25519HPKEV1Format:
			// Known key formats are exactly 32 bytes; reject short, empty,
			// or odd-length material before callers trust it.
			if _, err := decodeLowerHex(fmt.Sprintf("crypto_material item %q data", item.ID), item.Data, 32); err != nil {
				return nil, nil, err
			}
		default:
			// Unknown formats still must carry non-empty, decodable
			// lowercase hex: the character class alone would admit
			// odd-length strings that no hex decoder accepts.
			if item.Data == "" {
				return nil, nil, fmt.Errorf("crypto_material item %q data is empty", item.ID)
			}
			if !lowerHexRE.MatchString(item.Data) || len(item.Data)%2 != 0 {
				return nil, nil, fmt.Errorf("crypto_material item %q data is not lowercase hex", item.ID)
			}
		}
	}

	return &cm, cryptoBytes, nil
}

// deviceEvidenceSection is the endorsed device_evidence section envelope.
// Empty device evidence is Items: [] — the section is always present.
type deviceEvidenceSection struct {
	Format string               `json:"format"`
	Items  []DeviceEvidenceItem `json:"items"`
}

// DeviceEvidenceItem is one device's evidence; the item format URI versions
// the Evidence payload.
type DeviceEvidenceItem struct {
	ID       string         `json:"id"`
	Kind     string         `json:"kind"`
	Vendor   string         `json:"vendor"`
	Format   string         `json:"format"`
	Evidence jsontext.Value `json:"evidence"`
}

func parseDeviceEvidence(encoded string) (*deviceEvidenceSection, []byte, error) {
	if encoded == "" {
		return nil, nil, fmt.Errorf("device_evidence section is missing")
	}
	deviceBytes, err := decodeCanonicalBase64("device_evidence", encoded)
	if err != nil {
		return nil, nil, err
	}

	var de deviceEvidenceSection
	if err := json.Unmarshal(deviceBytes, &de, json.RejectUnknownMembers(true)); err != nil {
		return nil, nil, fmt.Errorf("parsing device_evidence: %w", err)
	}
	if de.Format != DeviceEvidenceV1Format {
		return nil, nil, fmt.Errorf("unsupported device_evidence section format %q", de.Format)
	}
	if de.Items == nil {
		return nil, nil, fmt.Errorf("device_evidence.items is missing")
	}
	seen := make(map[string]bool, len(de.Items))
	for _, item := range de.Items {
		if item.ID == "" {
			return nil, nil, fmt.Errorf("device_evidence item has no id")
		}
		if seen[item.ID] {
			return nil, nil, fmt.Errorf("duplicate device_evidence item id %q", item.ID)
		}
		seen[item.ID] = true
	}

	return &de, deviceBytes, nil
}

// ComputeReportData derives the 64-byte REPORT_DATA per the
// https://tinfoil.sh/report-data/v1 algorithm: SHA-256 over the algorithm
// URI (domain-separation label) followed by the three fixed-length 32-byte
// inputs in order.
func ComputeReportData(nonce, cryptoMaterialHash, deviceEvidenceHash []byte) ([64]byte, error) {
	var out [64]byte
	if len(nonce) != 32 || len(cryptoMaterialHash) != 32 || len(deviceEvidenceHash) != 32 {
		return out, fmt.Errorf("report data inputs must be 32 bytes each (got %d, %d, %d)",
			len(nonce), len(cryptoMaterialHash), len(deviceEvidenceHash))
	}
	h := sha256.New()
	h.Write([]byte(ReportDataV1Algorithm))
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

// Parse strictly parses a v3 document and checks its challenge bindings
// against expectedNonce, the nonce the caller sent: nonce equality,
// endorsed-section hash recomputation, and REPORT_DATA recomputation. The
// returned document carries the REPORT_DATA its CPU quote must bind, from
// ExpectedReportData.
//
// Parsing is strict: unknown members reject (case-sensitively), duplicate
// member names reject everywhere, hex must be lowercase, base64 canonical,
// and item ids unique. A parsed document is not authenticated: nothing in it
// is trusted until the quote proves the hardware bound that REPORT_DATA.
func Parse(docBytes, expectedNonce []byte) (result *Document, err error) {
	defer func() { err = errs.WrapAttestation(err) }()
	if len(expectedNonce) != NonceSize {
		return nil, &errs.ConfigurationError{Err: fmt.Errorf("expected nonce must be %d bytes, got %d", NonceSize, len(expectedNonce))}
	}
	doc, err := decode(docBytes)
	if err != nil {
		return nil, err
	}
	if err := doc.bind(expectedNonce); err != nil {
		return nil, err
	}
	return doc, nil
}

// decode applies the structural rules alone; the endorsed sections are
// retained as raw bytes for hashing.
func decode(docBytes []byte) (*Document, error) {
	var wire rawDocument
	if err := json.Unmarshal(docBytes, &wire, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("parsing attestation document: %w", err)
	}

	if wire.Format != AttestationV3Format {
		return nil, fmt.Errorf("unsupported document format %q", wire.Format)
	}

	if err := wire.Challenge.parse(); err != nil {
		return nil, err
	}

	report, err := wire.CPUEvidence.parse()
	if err != nil {
		return nil, err
	}

	cm, cryptoBytes, err := parseCryptoMaterial(wire.CryptoMaterial)
	if err != nil {
		return nil, err
	}

	de, deviceBytes, err := parseDeviceEvidence(wire.DeviceEvidence)
	if err != nil {
		return nil, err
	}

	if err := validateCollateral(wire.Collateral); err != nil {
		return nil, err
	}

	return &Document{
		challenge:           wire.Challenge,
		endorsed:            wire.CPUEvidence.Endorsed,
		evidence:            CPUEvidence{Format: wire.CPUEvidence.Format, Report: report},
		collateral:          wire.Collateral,
		cryptoMaterialBytes: cryptoBytes,
		deviceEvidenceBytes: deviceBytes,
		cryptoMaterial:      cm,
		deviceEvidence:      de,
	}, nil
}

// CPUEvidence returns a copy of the document's decoded CPU evidence.
func (d *Document) CPUEvidence() CPUEvidence {
	return d.evidence.Clone()
}

// CryptoMaterialItems returns a copy of the parsed crypto_material items.
func (d *Document) CryptoMaterialItems() []CryptoMaterialItem {
	if d.cryptoMaterial == nil {
		return nil
	}
	return slices.Clone(d.cryptoMaterial.Items)
}

// DeviceEvidenceItems returns a deep copy of the parsed device_evidence items.
func (d *Document) DeviceEvidenceItems() []DeviceEvidenceItem {
	if d.deviceEvidence == nil {
		return nil
	}
	items := slices.Clone(d.deviceEvidence.Items)
	for i := range items {
		items[i].Evidence = slices.Clone(items[i].Evidence)
	}
	return items
}

// CryptoMaterialItem returns a copy of the crypto_material item with the given id.
func (d *Document) CryptoMaterialItem(id string) (*CryptoMaterialItem, bool) {
	if d.cryptoMaterial == nil {
		return nil, false
	}
	for _, item := range d.cryptoMaterial.Items {
		if item.ID == id {
			return &item, true
		}
	}
	return nil, false
}

// ExpectedReportData is the REPORT_DATA the document's CPU quote must bind,
// recomputed by Parse from the caller's nonce and the endorsed sections. ok
// is false for a nil document or one that did not come from Parse, whose
// zero REPORT_DATA must never be compared against a quote.
func (d *Document) ExpectedReportData() (reportData [64]byte, ok bool) {
	if d == nil || !d.bound {
		return reportData, false
	}
	return d.reportData, true
}

// bind checks the challenge bindings of a decoded document against the
// caller's nonce and records the recomputed REPORT_DATA.
func (d *Document) bind(expectedNonce []byte) error {
	if d.challenge.Nonce != hex.EncodeToString(expectedNonce) {
		return fmt.Errorf("challenge nonce does not match the expected nonce")
	}

	cryptoHash := sha256.Sum256(d.cryptoMaterialBytes)
	deviceHash := sha256.Sum256(d.deviceEvidenceBytes)
	if hex.EncodeToString(cryptoHash[:]) != d.endorsed.CryptoMaterialHash {
		return fmt.Errorf("crypto_material hash does not match cpu_evidence.endorsed.crypto_material_hash")
	}
	if hex.EncodeToString(deviceHash[:]) != d.endorsed.DeviceEvidenceHash {
		return fmt.Errorf("device_evidence hash does not match cpu_evidence.endorsed.device_evidence_hash")
	}

	reportData, err := ComputeReportData(expectedNonce, cryptoHash[:], deviceHash[:])
	if err != nil {
		return err
	}
	if hex.EncodeToString(reportData[:]) != d.challenge.ReportData {
		return fmt.Errorf("challenge report_data does not match the recomputed value")
	}
	d.reportData = reportData
	d.bound = true
	return nil
}
