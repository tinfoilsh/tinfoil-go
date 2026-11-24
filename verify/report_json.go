package verify

import (
	"encoding/json/v2"
	"time"

	"github.com/tinfoilsh/tinfoil-go/internal/sdkinfo"
	"github.com/tinfoilsh/tinfoil-go/verify/measurement"
)

// ReportSchemaVersion is the schema_version that the JSON form of a
// VerificationReport carries. Adding a field keeps the version; removing or
// renaming one, or changing what one means, bumps it. A consumer ignores
// fields that it does not know.
const ReportSchemaVersion = 1

// The platform names of a measurement in the JSON form. A consumer tolerates
// a platform that it does not know.
const (
	measurementPlatformSEVSNP = "sev-snp"
	measurementPlatformTDX    = "tdx"
)

// MarshalJSON encodes the report in the JSON form that every Tinfoil SDK
// writes, so that a report can be shown or passed on, for example to a
// browser or another process:
//
//	{
//	  "schema_version": 1,
//	  "steps": [
//	    {"layer": "envelope", "status": "passed"},
//	    {"layer": "provenance", "status": "passed"},
//	    {"layer": "quote", "status": "failed", "message": "<detail>"},
//	    {"layer": "policy", "status": "not_run"}
//	  ],
//	  "verified_facts": { ...on success only, as VerifiedFacts.MarshalJSON writes it... },
//	  "partial_facts": { ...on a rejection only, as PartialFacts.MarshalJSON writes it... },
//	  "metadata": {
//	    "verified_at": "<RFC 3339, UTC>",
//	    "verifier": {"name": "tinfoil-go", "version": "<version>"},
//	    "host": "<host[:port]>"
//	  }
//	}
//
// Keys are snake_case, hex is lowercase and times are RFC 3339 in UTC. A fact
// that was not established is omitted, but an established fact that is empty
// is kept, as in "measured": {}; no member is null or "". Exactly one of
// verified_facts and partial_facts is present. A step's message is present
// only for a failed or skipped step. metadata.verifier is present only for a
// released version of this module. metadata.host is present only in a report
// that a client produced: it names the host that the client contacted, which
// is not attested, so it proves nothing about the enclave.
//
// The JSON is for display and transport only. It never authorizes anything:
// nothing in this package parses it back into a report or into verified
// facts, and a holder of the JSON cannot tell whether it came from a
// verifier, so a channel binds only to the VerifiedFacts that a verification
// returned in process.
func (r VerificationReport) MarshalJSON() ([]byte, error) {
	steps := r.Steps
	if steps == nil {
		steps = []Step{}
	}
	return json.Marshal(reportJSON{
		SchemaVersion: ReportSchemaVersion,
		Steps:         steps,
		VerifiedFacts: r.VerifiedFacts,
		PartialFacts:  r.PartialFacts,
		Metadata:      r.Metadata,
	})
}

type reportJSON struct {
	SchemaVersion int                  `json:"schema_version"`
	Steps         []Step               `json:"steps"`
	VerifiedFacts *VerifiedFacts       `json:"verified_facts,omitzero"`
	PartialFacts  *PartialFacts        `json:"partial_facts,omitzero"`
	Metadata      VerificationMetadata `json:"metadata"`
}

// MarshalJSON encodes the step as {"layer", "status", "message"}, without
// the message when it is empty.
func (s Step) MarshalJSON() ([]byte, error) {
	return json.Marshal(stepJSON{Layer: string(s.Layer), Status: string(s.Status), Message: s.Message})
}

type stepJSON struct {
	Layer   string `json:"layer"`
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

// MarshalJSON encodes the metadata as {"verified_at", "verifier", "host"}.
// The verifier is present only when its version is a release that Go's build
// information names: a development build, such as the gomobile bridge,
// which is built from source, can't name its own version reliably. The host
// is present only when a client set it.
func (m VerificationMetadata) MarshalJSON() ([]byte, error) {
	out := metadataJSON{VerifiedAt: formatReportTime(m.VerifiedAt), Host: m.Host}
	if m.Verifier.Name != "" && sdkinfo.IsRelease(m.Verifier.Version) {
		out.Verifier = &softwareIdentityJSON{Name: m.Verifier.Name, Version: m.Verifier.Version}
	}
	return json.Marshal(out)
}

type metadataJSON struct {
	VerifiedAt string                `json:"verified_at,omitempty"`
	Verifier   *softwareIdentityJSON `json:"verifier,omitzero"`
	Host       string                `json:"host,omitempty"`
}

type softwareIdentityJSON struct {
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
}

// MarshalJSON encodes the verified facts as the verified_facts object of the
// report's JSON form:
//
//	{
//	  "config_repo": "<owner/name>",
//	  "code_digest": "<hex>",
//	  "code_tag": "<tag>",
//	  "code_measurement": {"platform": "tdx", "rtmr1": "<hex>", "rtmr2": "<hex>"},
//	  "enclave_measurement": {"platform": "tdx", "mrtd": "<hex>", "rtmr0": "<hex>", ...},
//	  "config": {"source", "name", "digest", "reference", "signing_key_hint", "approval_time", "registry_id", "signature_time"},
//	  "runtime": {"source", "repo", "tag", "digest", "name", "commit", "approval_time"},
//	  "platform": {"source", "repo", "tag", "digest", "name", "commit", "approval_time"},
//	  "crypto_material": [{"id": "tls", "format": "<format>", "data": "<hex>"}],
//	  "freshness_expires_at": "<RFC 3339, UTC>"
//	}
//
// A measurement names its platform, "sev-snp" with "launch" or "tdx" with
// "mrtd" and "rtmr0" to "rtmr3", and omits a register that the release
// leaves to the platform; a code measurement that would hold no register is
// omitted. config, runtime and platform are present only for
// a config-based verification. The channel keys appear only in
// crypto_material.
//
// The JSON never authorizes a channel: see VerificationReport.MarshalJSON.
func (v VerifiedFacts) MarshalJSON() ([]byte, error) {
	out := verifiedFactsJSON{
		ConfigRepo:         v.configRepo,
		CodeDigest:         v.codeDigest,
		CodeTag:            v.codeTag,
		CodeMeasurement:    codeMeasurementJSON(v.codeMeasurement),
		EnclaveMeasurement: measurementJSONOf(v.enclaveMeasurement),
		Config:             configJSONOf(v.config),
		Runtime:            artifactJSONOf(v.runtime),
		Platform:           artifactJSONOf(v.platform),
		CryptoMaterial:     make([]cryptoMaterialJSON, 0, len(v.cryptoMaterial)),
		FreshnessExpiresAt: formatReportTime(v.freshnessExpiresAt),
	}
	for _, item := range v.cryptoMaterial {
		out.CryptoMaterial = append(out.CryptoMaterial, cryptoMaterialJSON{ID: item.ID, Format: item.Format, Data: item.Data})
	}
	return json.Marshal(out)
}

type verifiedFactsJSON struct {
	ConfigRepo         string               `json:"config_repo,omitempty"`
	CodeDigest         string               `json:"code_digest,omitempty"`
	CodeTag            string               `json:"code_tag,omitempty"`
	CodeMeasurement    *measurementJSON     `json:"code_measurement,omitzero"`
	EnclaveMeasurement *measurementJSON     `json:"enclave_measurement,omitzero"`
	Config             *configJSON          `json:"config,omitzero"`
	Runtime            *artifactJSON        `json:"runtime,omitzero"`
	Platform           *artifactJSON        `json:"platform,omitzero"`
	CryptoMaterial     []cryptoMaterialJSON `json:"crypto_material"`
	FreshnessExpiresAt string               `json:"freshness_expires_at,omitempty"`
}

type cryptoMaterialJSON struct {
	ID     string `json:"id,omitempty"`
	Format string `json:"format,omitempty"`
	Data   string `json:"data,omitempty"`
}

// MarshalJSON encodes the partial facts as the partial_facts object of the
// report's JSON form: {"expected", "measured"}, each present only once the
// step that establishes it passed, as ExpectedFacts and MeasuredFacts
// describe.
func (p PartialFacts) MarshalJSON() ([]byte, error) {
	return json.Marshal(partialFactsJSON(p))
}

type partialFactsJSON struct {
	Expected *ExpectedFacts `json:"expected,omitzero"`
	Measured *MeasuredFacts `json:"measured,omitzero"`
}

// MarshalJSON encodes the expected facts as {"config_repo", "artifact",
// "config", "platform", "code_measurement", "measurement"}, with the records
// and measurements as VerifiedFacts.MarshalJSON writes them. config and
// platform are present only for a config-based verification, and
// measurement only once the policy step resolved it.
func (e ExpectedFacts) MarshalJSON() ([]byte, error) {
	return json.Marshal(expectedFactsJSON{
		ConfigRepo:      e.ConfigRepo,
		Artifact:        *artifactJSONOf(&e.Artifact),
		Config:          configJSONOf(e.Config),
		Platform:        artifactJSONOf(e.Platform),
		CodeMeasurement: codeMeasurementJSON(e.CodeMeasurement),
		Measurement:     measurementJSONOf(e.Measurement),
	})
}

type expectedFactsJSON struct {
	ConfigRepo      string           `json:"config_repo,omitempty"`
	Artifact        artifactJSON     `json:"artifact"`
	Config          *configJSON      `json:"config,omitzero"`
	Platform        *artifactJSON    `json:"platform,omitzero"`
	CodeMeasurement *measurementJSON `json:"code_measurement,omitzero"`
	Measurement     *measurementJSON `json:"measurement,omitzero"`
}

// MarshalJSON encodes the measured facts as {"cpu_measurement",
// "tls_public_key_fp", "hpke_public_key_fp"}, each omitted when it is
// absent, so that facts with none of them encode as {}.
func (m MeasuredFacts) MarshalJSON() ([]byte, error) {
	out := measuredFactsJSON{TLSPublicKeyFP: m.TLSPublicKeyFP, HPKEPublicKeyFP: m.HPKEPublicKeyFP}
	if m.CPU != nil {
		out.CPUMeasurement = measurementJSONOf(m.CPU.Measurement)
	}
	return json.Marshal(out)
}

type measuredFactsJSON struct {
	CPUMeasurement  *measurementJSON `json:"cpu_measurement,omitzero"`
	TLSPublicKeyFP  string           `json:"tls_public_key_fp,omitempty"`
	HPKEPublicKeyFP string           `json:"hpke_public_key_fp,omitempty"`
}

// measurementJSON is a measurement or an expectation with named registers in
// lowercase hex, and without a register that an expectation leaves
// unconstrained.
type measurementJSON struct {
	Platform string `json:"platform,omitempty"`
	Launch   string `json:"launch,omitempty"`
	MRTD     string `json:"mrtd,omitempty"`
	RTMR0    string `json:"rtmr0,omitempty"`
	RTMR1    string `json:"rtmr1,omitempty"`
	RTMR2    string `json:"rtmr2,omitempty"`
	RTMR3    string `json:"rtmr3,omitempty"`
}

func measurementJSONOf(m measurement.Measurement) *measurementJSON {
	if m == nil {
		return nil
	}
	return expectedMeasurementJSON(m.Expected())
}

// codeMeasurementJSON is the registers that a release fixes, or nil when it
// fixes none, so that a code measurement without a register is omitted.
func codeMeasurementJSON(e measurement.Expected) *measurementJSON {
	out := expectedMeasurementJSON(e)
	if out == nil || *out == (measurementJSON{Platform: out.Platform}) {
		return nil
	}
	return out
}

func expectedMeasurementJSON(e measurement.Expected) *measurementJSON {
	hexOf := func(r *measurement.Register) string {
		if r == nil {
			return ""
		}
		return r.String()
	}
	switch e := e.(type) {
	case measurement.ExpectedSEVSNP:
		return &measurementJSON{Platform: measurementPlatformSEVSNP, Launch: hexOf(e.Launch)}
	case measurement.ExpectedTDX:
		return &measurementJSON{
			Platform: measurementPlatformTDX,
			MRTD:     hexOf(e.MRTD), RTMR0: hexOf(e.RTMR0), RTMR1: hexOf(e.RTMR1), RTMR2: hexOf(e.RTMR2), RTMR3: hexOf(e.RTMR3),
		}
	default:
		return nil
	}
}

// configJSON is a ConfigVerification in the report's JSON form. Only an
// endorsed config has a reference, signing key hint, registry ID or times.
type configJSON struct {
	Source         string `json:"source,omitempty"`
	Name           string `json:"name,omitempty"`
	Digest         string `json:"digest,omitempty"`
	Reference      string `json:"reference,omitempty"`
	SigningKeyHint string `json:"signing_key_hint,omitempty"`
	ApprovalTime   string `json:"approval_time,omitempty"`
	RegistryID     string `json:"registry_id,omitempty"`
	SignatureTime  string `json:"signature_time,omitempty"`
}

func configJSONOf(c *ConfigVerification) *configJSON {
	if c == nil {
		return nil
	}
	return &configJSON{
		Source: string(c.Source), Name: c.Name, Digest: c.Digest,
		Reference: c.Reference, SigningKeyHint: c.SigningKeyHint,
		ApprovalTime: formatReportTime(c.ApprovalTime), RegistryID: c.RegistryID,
		SignatureTime: formatReportTime(c.SignatureTime),
	}
}

// artifactJSON is an ArtifactVerification in the report's JSON form. An
// embedded artifact has no name, commit or approval time.
type artifactJSON struct {
	Source       string `json:"source,omitempty"`
	Repo         string `json:"repo,omitempty"`
	Tag          string `json:"tag,omitempty"`
	Digest       string `json:"digest,omitempty"`
	Name         string `json:"name,omitempty"`
	Commit       string `json:"commit,omitempty"`
	ApprovalTime string `json:"approval_time,omitempty"`
}

func artifactJSONOf(a *ArtifactVerification) *artifactJSON {
	if a == nil {
		return nil
	}
	return &artifactJSON{
		Source: string(a.Source), Repo: a.Repo, Tag: a.Tag, Digest: a.Digest,
		Name: a.Name, Commit: a.Commit, ApprovalTime: formatReportTime(a.ApprovalTime),
	}
}

// formatReportTime is RFC 3339 in UTC, or "" for the zero time of a fact
// that was not established.
func formatReportTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}
