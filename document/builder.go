package document

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"fmt"
	"slices"

	"github.com/tinfoilsh/tinfoil-go/document/collateral"
	"github.com/tinfoilsh/tinfoil-go/internal/errs"
)

// BuildInput is everything a v3 document carries besides its CPU evidence.
type BuildInput struct {
	// Nonce is the verifier's challenge, NonceSize bytes.
	Nonce []byte
	// CryptoMaterial and DeviceEvidence are the endorsed sections, hash-bound
	// into the quote's REPORT_DATA. A nil slice endorses no items.
	CryptoMaterial []CryptoMaterialItem
	DeviceEvidence []DeviceEvidenceItem
	// Collateral lets verifiers authenticate the evidence offline. It is not
	// endorsed: every entry is checked against its own signature chain.
	Collateral []collateral.Entry
}

// QuoteGenerator obtains a hardware quote whose REPORT_DATA is reportData,
// returning the evidence format (such as SEVSNPReportV1Format) and the raw
// report or quote.
type QuoteGenerator func(reportData [64]byte) (format string, report []byte, err error)

// Build produces a serialized v3 document for in: it serializes and hashes the
// endorsed sections, derives the REPORT_DATA they bind, has generateQuote sign
// it, and assembles the result.
//
// The input is held to the rules Parse enforces before any quote is generated,
// and Build derives every other field itself, so it never yields a document
// Parse would reject. Invalid input is a ConfigurationError. A failure of
// generateQuote, including evidence of an unknown format or an empty report,
// is not the caller's configuration error: it is returned unclassified. Build
// keeps no state and is safe for concurrent use.
func Build(in BuildInput, generateQuote QuoteGenerator) ([]byte, error) {
	if generateQuote == nil {
		return nil, &errs.ConfigurationError{Err: fmt.Errorf("a quote generator is required")}
	}
	// Copied so a caller reusing its buffer cannot change the nonce between
	// the REPORT_DATA the quote signs and the challenge the document carries.
	nonce := slices.Clone(in.Nonce)
	sections, err := endorse(nonce, in.CryptoMaterial, in.DeviceEvidence)
	if err != nil {
		return nil, &errs.ConfigurationError{Err: err}
	}
	// Parse decodes every entry of a known role and format; decoding them
	// here rejects one Parse would refuse before it costs a hardware quote.
	if _, err := collateral.Decode(in.Collateral); err != nil {
		return nil, &errs.ConfigurationError{Err: err}
	}
	// Serializing rejects what Decode does not check, such as invalid UTF-8
	// in an entry's ID.
	if _, err := json.Marshal(in.Collateral); err != nil {
		return nil, &errs.ConfigurationError{Err: fmt.Errorf("serializing collateral: %w", err)}
	}
	format, report, err := generateQuote(sections.reportData)
	if err != nil {
		return nil, err
	}
	if format != SEVSNPReportV1Format && format != TDXQuoteV1Format {
		return nil, fmt.Errorf("quote generator returned unsupported evidence format %q", format)
	}
	if len(report) == 0 {
		return nil, fmt.Errorf("quote generator returned an empty report")
	}
	docBytes, err := sections.assemble(nonce, format, report, in.Collateral)
	if err != nil {
		return nil, &errs.ConfigurationError{Err: err}
	}
	return docBytes, nil
}

// endorsed holds the serialized endorsed sections and the REPORT_DATA they
// bind for one nonce.
type endorsed struct {
	cryptoMaterial string
	deviceEvidence string
	cryptoHash     [32]byte
	deviceHash     [32]byte
	reportData     [64]byte
}

// endorse serializes each endorsed section once, holds it to Parse's rules,
// and derives the REPORT_DATA the sections bind for nonce.
func endorse(nonce []byte, cryptoMaterial []CryptoMaterialItem, deviceEvidence []DeviceEvidenceItem) (*endorsed, error) {
	if len(nonce) != NonceSize {
		return nil, fmt.Errorf("nonce must be %d bytes, got %d", NonceSize, len(nonce))
	}

	cryptoBytes, err := json.Marshal(cryptoMaterialSection{Format: CryptoMaterialV1Format, Items: cryptoMaterial})
	if err != nil {
		return nil, fmt.Errorf("serializing crypto_material: %w", err)
	}
	deviceBytes, err := json.Marshal(deviceEvidenceSection{Format: DeviceEvidenceV1Format, Items: deviceEvidence})
	if err != nil {
		return nil, fmt.Errorf("serializing device_evidence: %w", err)
	}
	e := &endorsed{
		cryptoMaterial: base64.StdEncoding.EncodeToString(cryptoBytes),
		deviceEvidence: base64.StdEncoding.EncodeToString(deviceBytes),
		cryptoHash:     sha256.Sum256(cryptoBytes),
		deviceHash:     sha256.Sum256(deviceBytes),
	}
	if _, _, err := parseCryptoMaterial(e.cryptoMaterial); err != nil {
		return nil, err
	}
	if _, _, err := parseDeviceEvidence(e.deviceEvidence); err != nil {
		return nil, err
	}
	e.reportData, err = ComputeReportData(nonce, e.cryptoHash[:], e.deviceHash[:])
	if err != nil {
		return nil, err
	}
	return e, nil
}

// assemble serializes the complete document.
func (e *endorsed) assemble(nonce []byte, format string, report []byte, entries []collateral.Entry) ([]byte, error) {
	docBytes, err := json.Marshal(rawDocument{
		Format: AttestationV3Format,
		Challenge: challenge{
			Nonce:               hex.EncodeToString(nonce),
			ReportData:          hex.EncodeToString(e.reportData[:]),
			ReportDataAlgorithm: ReportDataV1Algorithm,
		},
		CPUEvidence: rawCPUEvidence{
			Format:       format,
			ReportBase64: base64.StdEncoding.EncodeToString(report),
			Endorsed: endorsedHashes{
				CryptoMaterialHash: hex.EncodeToString(e.cryptoHash[:]),
				DeviceEvidenceHash: hex.EncodeToString(e.deviceHash[:]),
			},
		},
		CryptoMaterial: e.cryptoMaterial,
		DeviceEvidence: e.deviceEvidence,
		Collateral:     entries,
	})
	if err != nil {
		return nil, fmt.Errorf("serializing attestation document: %w", err)
	}
	return docBytes, nil
}
