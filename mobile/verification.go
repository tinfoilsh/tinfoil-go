package mobile

import (
	"fmt"
	"time"

	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/document"
	"github.com/tinfoilsh/tinfoil-go/verify/measurement"
)

// VerificationSchemaVersion identifies the result JSON below. It changes when
// a field is removed or its meaning changes, so a caller can refuse a payload
// it does not understand rather than read a renamed field as absent. Version
// 2 replaced the verification object of version 1 with the result object and
// its verification report.
const VerificationSchemaVersion = 2

// resultJSON is what Verify returns for a verification that ran: the
// verifier accepted the document, or rejected it with a VerificationError.
// This struct and the ones that it contains are the schema of the FFI
// contract that the Swift and Kotlin SDKs decode. The schema is expected to
// remain stable, to decouple the internal implementation details of the Go
// SDK from the interface that Swift and Kotlin see. Avoid changing it if
// possible.
//
// If it needs non-backwards-compatible modifications, be sure to:
// 1. Bump the VerificationSchemaVersion
// 2. Update the code that decodes it in the tinfoil-swift and tinfoil-kt SDKs
// 3. Update tests/mobile/Smoke.swift and tests/mobile/Smoke.java
//
// The JSON, with every optional member shown:
//
//	{
//	  "schema_version": 2,
//	  "report": {
//	    "steps": [
//	      {"layer": "envelope", "status": "passed"},
//	      {"layer": "provenance", "status": "passed"},
//	      {"layer": "quote", "status": "failed", "message": "verification error: quote: <detail>"},
//	      {"layer": "policy", "status": "not_run"}
//	    ],
//	    "verified_facts": { ...verifiedFactsJSON, on success only... },
//	    "partial_facts": {
//	      "expected": {
//	        "config_repo": "<owner/name>",
//	        "artifact": { ...artifactJSON... },
//	        "config": { ...configJSON... },
//	        "platform": { ...artifactJSON... },
//	        "code_measurement": {"type": "<measurement type>", "registers": ["<hex or empty>", "..."]},
//	        "measurement": {"type": "<measurement type>", "registers": ["<hex>", "..."]}
//	      },
//	      "measured": {
//	        "cpu_measurement": {"type": "<measurement type>", "registers": ["<hex>", "..."]},
//	        "tls_public_key_fp": "<hex>",
//	        "hpke_public_key_fp": "<hex>"
//	      }
//	    },
//	    "metadata": {"verified_at": "<RFC 3339>"}
//	  },
//	  "error": {"layer": "quote", "message": "verification error: quote: <detail>"}
//	}
//
// On success, error is absent and the report carries verified_facts and no
// partial_facts. On a rejection, error is present, and the report carries
// partial_facts and no verified_facts; the caller throws its verification
// error with the report. The steps are envelope, provenance, quote and
// policy, in that order, each "passed", "failed", "skipped" or "not_run";
// more layers may be added, so a caller tolerates a layer that it doesn't
// know. A failed step's message is the error's message, and a skipped
// step's is the reason; other steps have none. In partial_facts, expected is
// present once provenance passed or was skipped, and measured once the
// envelope passed. code_measurement is in the layout of the platform that
// the document's evidence names, with "" for a register that the release
// leaves to the platform. measurement, the full set of registers that the
// quote had to attest, is present only once the policy step resolved it, and
// cpu_measurement only once the quote step passed. The key fingerprints in
// a rejection are only the document's claim, never verified, and a report
// never carries a channel key: hpke_public_key_fp is the lowercase-hex
// SHA-256 of the HPKE key's bytes.
//
// Optional objects are omitted only when they are absent, never because
// they are empty: an envelope that passed for a document that endorses no
// keys still has "measured": {}.
type resultJSON struct {
	SchemaVersion int        `json:"schema_version"`
	Report        reportJSON `json:"report"`
	Error         *errorJSON `json:"error,omitzero"`
}

// errorJSON is a VerificationError: the layer that rejected the document, and
// the message in the format that errors.go describes.
type errorJSON struct {
	Layer   string `json:"layer"`
	Message string `json:"message"`
}

type reportJSON struct {
	Steps         []stepJSON         `json:"steps"`
	VerifiedFacts *verifiedFactsJSON `json:"verified_facts,omitzero"`
	PartialFacts  *partialFactsJSON  `json:"partial_facts,omitzero"`
	Metadata      metadataJSON       `json:"metadata"`
}

type stepJSON struct {
	Layer   string `json:"layer"`
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

// metadataJSON describes the verification. VerifiedAt is RFC 3339: the
// instant that the document was appraised at. The caller records which SDK
// did the verifying; this package is built from source, so it could only
// report its own version as "devel".
type metadataJSON struct {
	VerifiedAt string `json:"verified_at"`
}

type partialFactsJSON struct {
	Expected *expectedFactsJSON `json:"expected,omitzero"`
	Measured *measuredFactsJSON `json:"measured,omitzero"`
}

type expectedFactsJSON struct {
	ConfigRepo      string           `json:"config_repo"`
	Artifact        *artifactJSON    `json:"artifact"`
	Config          *configJSON      `json:"config,omitempty"`
	Platform        *artifactJSON    `json:"platform,omitempty"`
	CodeMeasurement *measurementJSON `json:"code_measurement,omitempty"`
	Measurement     *measurementJSON `json:"measurement,omitempty"`
}

type measuredFactsJSON struct {
	CPUMeasurement  *measurementJSON `json:"cpu_measurement,omitempty"`
	TLSPublicKeyFP  string           `json:"tls_public_key_fp,omitempty"`
	HPKEPublicKeyFP string           `json:"hpke_public_key_fp,omitempty"`
}

// verifiedFactsJSON is what a verification proved.
type verifiedFactsJSON struct {
	ConfigRepo string `json:"config_repo"`

	CodeDigest         string           `json:"code_digest"`
	CodeTag            string           `json:"code_tag,omitempty"`
	CodeMeasurement    *measurementJSON `json:"code_measurement,omitempty"`
	EnclaveMeasurement *measurementJSON `json:"enclave_measurement,omitempty"`

	// Config, Runtime and Platform describe a deployment verified from its
	// config, and are absent for one verified against a code release.
	Config   *configJSON   `json:"config,omitempty"`
	Runtime  *artifactJSON `json:"runtime,omitempty"`
	Platform *artifactJSON `json:"platform,omitempty"`

	// TLSPublicKeyFP and HPKEPublicKey are lifted out of CryptoMaterial by ID
	// and format, because binding a channel to them is what a caller does with
	// verified facts. A TLS-only enclave endorses no HPKE key.
	TLSPublicKeyFP string `json:"tls_public_key_fp"`
	HPKEPublicKey  string `json:"hpke_public_key,omitempty"`
	// CryptoMaterial carries every endorsed item, including any this contract
	// does not lift out.
	CryptoMaterial []cryptoMaterialJSON `json:"crypto_material"`

	// FreshnessExpiresAt is RFC 3339. A caller must stop authorizing new
	// requests at or after it, and verify again.
	FreshnessExpiresAt string `json:"freshness_expires_at"`
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

// configJSON is the config bound to the hardware. Source is "endorsement",
// "embedded" or "policy" (a ConfigAuthorizer approved it). Only an endorsed
// config has a reference, signing key hint, registry ID or times; an absent
// one is omitted. Times are RFC 3339.
type configJSON struct {
	Source         string `json:"source"`
	Name           string `json:"name,omitempty"`
	Digest         string `json:"digest"`
	Reference      string `json:"reference,omitempty"`
	SigningKeyHint string `json:"signing_key_hint,omitempty"`
	ApprovalTime   string `json:"approval_time,omitempty"`
	RegistryID     string `json:"registry_id,omitempty"`
	SignatureTime  string `json:"signature_time,omitempty"`
}

// artifactJSON is a code release, or a runtime or platform artifact that a
// config-based verification accepted. Source is "endorsement" or "embedded";
// an embedded artifact has no name, commit or approval time, and an embedded
// platform has only a digest.
type artifactJSON struct {
	Source       string `json:"source"`
	Repo         string `json:"repo,omitempty"`
	Tag          string `json:"tag,omitempty"`
	Digest       string `json:"digest"`
	Name         string `json:"name,omitempty"`
	Commit       string `json:"commit,omitempty"`
	ApprovalTime string `json:"approval_time,omitempty"`
}

type cryptoMaterialJSON struct {
	ID     string `json:"id"`
	Format string `json:"format"`
	Data   string `json:"data"`
}

// toResultJSON maps the outcome of a verification that ran onto the
// contract: report for an accepted document, or rejected for a rejected one.
func toResultJSON(report *verify.VerificationReport, rejected *verify.VerificationError) resultJSON {
	out := resultJSON{SchemaVersion: VerificationSchemaVersion}
	if rejected != nil {
		report = rejected.Report
		out.Error = &errorJSON{Layer: string(rejected.Layer), Message: toMobileError(rejected).Error()}
	}
	out.Report = toReportJSON(report)
	if out.Error != nil {
		// A failed step's message is the error's, in the bridge's format.
		for i := range out.Report.Steps {
			if out.Report.Steps[i].Status == string(verify.StepFailed) {
				out.Report.Steps[i].Message = out.Error.Message
			}
		}
	}
	return out
}

func toReportJSON(r *verify.VerificationReport) reportJSON {
	out := reportJSON{Steps: []stepJSON{}}
	if r == nil {
		return out
	}
	for _, s := range r.Steps {
		out.Steps = append(out.Steps, stepJSON{Layer: string(s.Layer), Status: string(s.Status), Message: s.Message})
	}
	out.Metadata.VerifiedAt = formatTime(r.Metadata.VerifiedAt)
	if r.VerifiedFacts != nil {
		facts := toVerifiedFactsJSON(r.VerifiedFacts)
		out.VerifiedFacts = &facts
	}
	if p := r.PartialFacts; p != nil {
		out.PartialFacts = &partialFactsJSON{}
		if e := p.Expected; e != nil {
			out.PartialFacts.Expected = &expectedFactsJSON{
				ConfigRepo:      e.ConfigRepo,
				Artifact:        toArtifactJSON(e.Artifact),
				CodeMeasurement: toExpectedJSON(e.CodeMeasurement),
				Measurement:     toMeasurementJSON(e.Measurement),
			}
			if e.Config != nil {
				out.PartialFacts.Expected.Config = toConfigJSON(*e.Config)
			}
			if e.Platform != nil {
				out.PartialFacts.Expected.Platform = toArtifactJSON(*e.Platform)
			}
		}
		if m := p.Measured; m != nil {
			out.PartialFacts.Measured = &measuredFactsJSON{TLSPublicKeyFP: m.TLSPublicKeyFP, HPKEPublicKeyFP: m.HPKEPublicKeyFP}
			if m.CPU != nil {
				out.PartialFacts.Measured.CPUMeasurement = toMeasurementJSON(m.CPU.Measurement)
			}
		}
	}
	return out
}

// toVerifiedFactsJSON maps verified facts onto the contract. A missing
// endorsed key is left empty rather than failing: the document is verified
// either way, and a caller that needs a channel key checks for it.
func toVerifiedFactsJSON(v *verify.VerifiedFacts) verifiedFactsJSON {
	items := v.CryptoMaterial()
	out := verifiedFactsJSON{
		ConfigRepo:         v.ConfigRepo(),
		CodeDigest:         v.CodeDigest(),
		CodeTag:            v.CodeTag(),
		CodeMeasurement:    toExpectedJSON(v.CodeMeasurement()),
		EnclaveMeasurement: toMeasurementJSON(v.EnclaveMeasurement()),
		CryptoMaterial:     make([]cryptoMaterialJSON, 0, len(items)),
		FreshnessExpiresAt: v.FreshnessExpiresAt().UTC().Format(time.RFC3339Nano),
	}
	if config, ok := v.Config(); ok {
		out.Config = toConfigJSON(config)
	}
	if runtime, ok := v.Runtime(); ok {
		out.Runtime = toArtifactJSON(runtime)
	}
	if platform, ok := v.Platform(); ok {
		out.Platform = toArtifactJSON(platform)
	}
	out.TLSPublicKeyFP, _ = v.CryptoMaterialData(document.CryptoMaterialIDTLS, document.KeySPKIFPSHA256V1Format)
	out.HPKEPublicKey, _ = v.CryptoMaterialData(document.CryptoMaterialIDHPKE, document.KeyX25519HPKEV1Format)
	for _, item := range items {
		out.CryptoMaterial = append(out.CryptoMaterial, cryptoMaterialJSON{ID: item.ID, Format: item.Format, Data: item.Data})
	}
	return out
}

func toConfigJSON(config verify.ConfigVerification) *configJSON {
	return &configJSON{
		Source: string(config.Source), Name: config.Name, Digest: config.Digest,
		Reference: config.Reference, SigningKeyHint: config.SigningKeyHint,
		ApprovalTime: formatTime(config.ApprovalTime), RegistryID: config.RegistryID,
		SignatureTime: formatTime(config.SignatureTime),
	}
}

func toArtifactJSON(a verify.ArtifactVerification) *artifactJSON {
	return &artifactJSON{
		Source: string(a.Source), Repo: a.Repo, Tag: a.Tag, Digest: a.Digest,
		Name: a.Name, Commit: a.Commit, ApprovalTime: formatTime(a.ApprovalTime),
	}
}

// formatTime is RFC 3339, or "" for the zero time of an absent fact.
func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
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
