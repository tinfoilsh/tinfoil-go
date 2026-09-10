package attestation

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"

	"github.com/tinfoilsh/tinfoil-go/verifier/util"
)

const (
	attestationV3   PredicateType = "https://tinfoil.sh/predicate/attestation/v3"
	reportDataV1                  = "https://tinfoil.sh/report-data/v1"
	sevSnpReportV1                = "https://tinfoil.sh/format/sev-snp-report/v1"
	tdxQuoteV1                    = "https://tinfoil.sh/format/tdx-quote/v1"
	keySpkiFpSha256               = "https://tinfoil.sh/key/spki-fp-sha256/v1"
	keyX25519HPKE                 = "https://tinfoil.sh/key/x25519-hpke/v1"

	nonceSize = 32
)

// ErrNonceUnbound reports a quote whose REPORT_DATA is not the one the
// challenge derives, so the enclave answered with a report it did not take out
// for this verifier.
var ErrNonceUnbound = errors.New("quote does not bind the challenge nonce")

// documentV3 is the part of a nonce-bound attestation document a verifier
// needs. The endorsed sections travel base64-encoded so their hashes cover the
// exact bytes the enclave hashed into REPORT_DATA, with no re-serialization.
type documentV3 struct {
	Format      PredicateType `json:"format"`
	CPUEvidence struct {
		Format       string `json:"format"`
		ReportBase64 string `json:"report_base64"`
	} `json:"cpu_evidence"`
	CryptoMaterial string `json:"crypto_material"`
	DeviceEvidence string `json:"device_evidence"`
}

// FetchNonced fetches an attestation document over a nonce this process
// generates and verifies the hardware took the quote out for it. A boot-time
// report cannot answer the challenge, so the enclave proves the state it is in
// now: registers a runtime extend has already reached, and keys it still holds.
func FetchNonced(host string) (*Verification, error) {
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %v", err)
	}

	u := url.URL{
		Scheme:   "https",
		Host:     host,
		Path:     attestationEndpoint,
		RawQuery: url.Values{"nonce": {hex.EncodeToString(nonce)}}.Encode(),
	}
	body, _, err := util.Get(u.String())
	if err != nil {
		return nil, err
	}
	return verifyNonced(body, nonce)
}

// verifyNonced authenticates a document against the nonce the verifier chose.
// REPORT_DATA is SHA-256 over the algorithm URI, the nonce, and the hashes of
// the two endorsed sections; recomputing it from our own nonce and finding it
// in the quote is what proves the report is this challenge's answer, and only
// then do the keys the document endorses mean anything.
func verifyNonced(body, nonce []byte) (*Verification, error) {
	var doc documentV3
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("parsing attestation document: %v", err)
	}
	if doc.Format != attestationV3 {
		return nil, fmt.Errorf("unsupported attestation format: %s", doc.Format)
	}
	cryptoMaterial, err := base64.StdEncoding.DecodeString(doc.CryptoMaterial)
	if err != nil {
		return nil, fmt.Errorf("decoding crypto material: %v", err)
	}
	deviceEvidence, err := base64.StdEncoding.DecodeString(doc.DeviceEvidence)
	if err != nil {
		return nil, fmt.Errorf("decoding device evidence: %v", err)
	}
	cryptoHash := sha256.Sum256(cryptoMaterial)
	deviceHash := sha256.Sum256(deviceEvidence)

	h := sha256.New()
	h.Write([]byte(reportDataV1))
	h.Write(nonce)
	h.Write(cryptoHash[:])
	h.Write(deviceHash[:])
	expectedReportData := make([]byte, 64)
	copy(expectedReportData, h.Sum(nil))

	var measurement *Measurement
	var reportData []byte
	switch doc.CPUEvidence.Format {
	case sevSnpReportV1:
		report, err := verifySevReport(doc.CPUEvidence.ReportBase64, false, nil)
		if err != nil {
			return nil, err
		}
		measurement = &Measurement{
			Type:      SevGuestV2,
			Registers: []string{hex.EncodeToString(report.Measurement)},
		}
		reportData = report.ReportData
	case tdxQuoteV1:
		registers, quoted, err := verifyTdxReport(doc.CPUEvidence.ReportBase64, false)
		if err != nil {
			return nil, err
		}
		measurement = &Measurement{Type: TdxGuestV2, Registers: registers}
		reportData = quoted
	default:
		return nil, fmt.Errorf("unsupported CPU evidence format: %s", doc.CPUEvidence.Format)
	}

	if !bytes.Equal(reportData, expectedReportData) {
		return nil, ErrNonceUnbound
	}

	var keys struct {
		Items []struct {
			ID     string `json:"id"`
			Format string `json:"format"`
			Data   string `json:"data"`
		} `json:"items"`
	}
	if err := json.Unmarshal(cryptoMaterial, &keys); err != nil {
		return nil, fmt.Errorf("parsing crypto material: %v", err)
	}
	verification := &Verification{Measurement: measurement, Nonce: hex.EncodeToString(nonce)}
	for _, key := range keys.Items {
		switch {
		case key.ID == "tls" && key.Format == keySpkiFpSha256:
			verification.TLSPublicKeyFP = key.Data
		case key.ID == "hpke" && key.Format == keyX25519HPKE:
			verification.HPKEPublicKey = key.Data
		}
	}
	if verification.TLSPublicKeyFP == "" {
		return nil, fmt.Errorf("attestation endorses no TLS public key")
	}
	return verification, nil
}
