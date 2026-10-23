package mobile

import (
	"fmt"
	"time"

	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/document"
	"github.com/tinfoilsh/tinfoil-go/verify/measurement"
)

// VerificationSchemaVersion identifies the JSON below. It changes when a field
// is removed or its meaning changes, so a caller can refuse a payload it does
// not understand rather than read a renamed field as absent.
const VerificationSchemaVersion = 1

// verificationJSON is the payload a caller decodes. This struct is the schema
// that forms the FFI contract that the Swift SDK expects. This schema is
// expected to remain stable to decouple the internal implementation details of
// the Go SDK from the interface that Swift sees. Avoid changing this struct if
// possible.
//
// If this struct needs non-backwards-compatible modifications, be sure to:
// 1. Bump the VerificationSchemaVersion
// 2. Update the code that decodes this struct in the tinfoil-swift SDK
// 3. Update tests/mobile/Smoke.swift
type verificationJSON struct {
	SchemaVersion int    `json:"schema_version"`
	ConfigRepo    string `json:"config_repo"`

	CodeDigest         string           `json:"code_digest"`
	CodeTag            string           `json:"code_tag,omitempty"`
	CodeMeasurement    *measurementJSON `json:"code_measurement,omitempty"`
	EnclaveMeasurement *measurementJSON `json:"enclave_measurement,omitempty"`

	// TLSPublicKeyFP and HPKEPublicKey are lifted out of CryptoMaterial by ID
	// and format, because binding a channel to them is what a caller does with
	// a verification. A TLS-only enclave endorses no HPKE key.
	TLSPublicKeyFP string `json:"tls_public_key_fp"`
	HPKEPublicKey  string `json:"hpke_public_key,omitempty"`
	// CryptoMaterial carries every endorsed item, including any this contract
	// does not lift out.
	CryptoMaterial []cryptoMaterialJSON `json:"crypto_material"`

	// FreshnessExpiresAt is RFC 3339. A caller must stop authorizing new
	// requests at or after it, and verify again.
	FreshnessExpiresAt string `json:"freshness_expires_at"`

	// VerifiedAt is RFC 3339: the instant the document was appraised at. The
	// caller records which SDK did the verifying; this package is built from
	// source, so it could only report its own version as "devel".
	VerifiedAt string `json:"verified_at"`
}

// measurementJSON is a measurement in the contract: a type and its registers
// in platform order, lowercase hex, with "" for an unconstrained register.
type measurementJSON struct {
	Type      string   `json:"type"`
	Registers []string `json:"registers"`
}

// The measurement types of the contract.
const (
	sevSNPMeasurementType = "https://tinfoil.sh/predicate/sev-snp-guest/v2"
	tdxMeasurementType    = "https://tinfoil.sh/predicate/tdx-guest/v2"
)

type cryptoMaterialJSON struct {
	ID     string `json:"id"`
	Format string `json:"format"`
	Data   string `json:"data"`
}

// toVerificationJSON maps a verification onto the contract. A missing
// endorsed key is left empty rather than failing: the document is verified
// either way, and a caller that needs a channel key checks for it.
func toVerificationJSON(v *verify.Verification) verificationJSON {
	out := verificationJSON{
		SchemaVersion:      VerificationSchemaVersion,
		ConfigRepo:         v.ConfigRepo,
		CodeDigest:         v.CodeDigest,
		CodeTag:            v.CodeTag,
		CodeMeasurement:    toExpectedJSON(v.CodeMeasurement),
		EnclaveMeasurement: toMeasurementJSON(v.EnclaveMeasurement),
		CryptoMaterial:     make([]cryptoMaterialJSON, 0, len(v.CryptoMaterial)),
		FreshnessExpiresAt: v.FreshnessExpiresAt.UTC().Format(time.RFC3339Nano),
		VerifiedAt:         v.Metadata.VerifiedAt.UTC().Format(time.RFC3339Nano),
	}
	out.TLSPublicKeyFP, _ = v.CryptoMaterialData(document.CryptoMaterialIDTLS, document.KeySPKIFPSHA256V1Format)
	out.HPKEPublicKey, _ = v.CryptoMaterialData(document.CryptoMaterialIDHPKE, document.KeyX25519HPKEV1Format)
	for _, item := range v.CryptoMaterial {
		out.CryptoMaterial = append(out.CryptoMaterial, cryptoMaterialJSON{ID: item.ID, Format: item.Format, Data: item.Data})
	}
	return out
}

func toMeasurementJSON(m measurement.Measurement) *measurementJSON {
	switch m := m.(type) {
	case measurement.SEVSNP:
		return &measurementJSON{Type: sevSNPMeasurementType, Registers: []string{m.Launch.String()}}
	case measurement.TDX:
		return &measurementJSON{Type: tdxMeasurementType, Registers: []string{m.MRTD.String(), m.RTMR0.String(), m.RTMR1.String(), m.RTMR2.String(), m.RTMR3.String()}}
	default:
		return nil
	}
}

func toExpectedJSON(e measurement.Expected) *measurementJSON {
	hexOf := func(r *measurement.Register) string {
		if r == nil {
			return ""
		}
		return r.String()
	}
	switch e := e.(type) {
	case measurement.ExpectedSEVSNP:
		return &measurementJSON{Type: sevSNPMeasurementType, Registers: []string{hexOf(e.Launch)}}
	case measurement.ExpectedTDX:
		return &measurementJSON{Type: tdxMeasurementType, Registers: []string{hexOf(e.MRTD), hexOf(e.RTMR0), hexOf(e.RTMR1), hexOf(e.RTMR2), hexOf(e.RTMR3)}}
	default:
		return nil
	}
}

// expected parses pinned registers, where "" leaves a register unpinned. A nil
// receiver pins nothing.
func (j *measurementJSON) expected() (measurement.Expected, error) {
	if j == nil {
		return nil, nil
	}
	r := j.Registers
	var pins measurement.Expected
	var err error
	switch j.Type {
	case sevSNPMeasurementType:
		if len(r) != 1 {
			return nil, fmt.Errorf("pinned registers require 1 entry, got %d", len(r))
		}
		pins, err = measurement.ParseExpectedSEVSNP(r[0])
	case tdxMeasurementType:
		if len(r) != 5 {
			return nil, fmt.Errorf("pinned registers require 5 entries, got %d", len(r))
		}
		pins, err = measurement.ParseExpectedTDX(r[0], r[1], r[2], r[3], r[4])
	default:
		return nil, fmt.Errorf("pinned registers require an SNP or TDX measurement type")
	}
	if err != nil {
		return nil, fmt.Errorf("pinned registers: %w", err)
	}
	return pins, nil
}
