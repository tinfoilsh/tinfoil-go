package mobile

import (
	"time"

	"github.com/tinfoilsh/tinfoil-go/verifier/client"
	"github.com/tinfoilsh/tinfoil-go/verifier/document"
	"github.com/tinfoilsh/tinfoil-go/verifier/measurement"
)

// VerificationSchemaVersion identifies the JSON below. It changes when a field
// is removed or its meaning changes, so a caller can refuse a payload it does
// not understand rather than read a renamed field as absent.
const VerificationSchemaVersion = 1

// verificationJSON is the contract a caller decodes. It is deliberately not
// the SDK's own verification type: that shape is internal and still moving,
// and serialising it would make every rename a silent break for callers who
// are never compiled against it. Editing this struct is editing the contract.
type verificationJSON struct {
	SchemaVersion int    `json:"schema_version"`
	ConfigRepo    string `json:"config_repo"`
	// EnclaveHost is empty when the verification contacted no enclave.
	EnclaveHost string `json:"enclave_host,omitempty"`

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

	Verifier   softwareIdentityJSON `json:"verifier"`
	VerifiedAt string               `json:"verified_at"`
}

type measurementJSON struct {
	Type      string   `json:"type"`
	Registers []string `json:"registers"`
}

type cryptoMaterialJSON struct {
	ID     string `json:"id"`
	Format string `json:"format"`
	Data   string `json:"data"`
}

type softwareIdentityJSON struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// toVerificationJSON maps the SDK's record onto the contract. A missing
// endorsed key is left empty rather than failing: the document is verified
// either way, and a caller that needs a channel key checks for it.
func toVerificationJSON(v *client.VerifiedDocumentV3) verificationJSON {
	out := verificationJSON{
		SchemaVersion:      VerificationSchemaVersion,
		ConfigRepo:         v.ConfigRepo,
		EnclaveHost:        v.EnclaveHost,
		CodeDigest:         v.CodeDigest,
		CodeTag:            v.CodeTag,
		CodeMeasurement:    toMeasurementJSON(v.CodeMeasurement),
		EnclaveMeasurement: toMeasurementJSON(v.EnclaveMeasurement),
		CryptoMaterial:     make([]cryptoMaterialJSON, 0, len(v.CryptoMaterial)),
		FreshnessExpiresAt: v.FreshnessExpiresAt.UTC().Format(time.RFC3339Nano),
		Verifier:           softwareIdentityJSON{Name: v.Verifier.Name, Version: v.Verifier.Version},
		VerifiedAt:         v.VerifiedAt,
	}
	out.TLSPublicKeyFP, _ = v.CryptoMaterialData(document.CryptoMaterialIDTLS, document.KeySPKIFPSHA256V1Format)
	out.HPKEPublicKey, _ = v.CryptoMaterialData(document.CryptoMaterialIDHPKE, document.KeyX25519HPKEV1Format)
	for _, item := range v.CryptoMaterial {
		out.CryptoMaterial = append(out.CryptoMaterial, cryptoMaterialJSON{ID: item.ID, Format: item.Format, Data: item.Data})
	}
	return out
}

func toMeasurementJSON(m *measurement.Measurement) *measurementJSON {
	if m == nil {
		return nil
	}
	return &measurementJSON{Type: string(m.Type), Registers: append([]string(nil), m.Registers...)}
}
