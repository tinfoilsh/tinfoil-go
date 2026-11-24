package mobile

import (
	"fmt"

	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/measurement"
)

// VerificationSchemaVersion identifies the result JSON below. It changes when
// a field is removed or its meaning changes, so a caller can refuse a payload
// that it does not understand rather than read a renamed field as absent.
// Version 2 replaced the verification object of version 1 with the result
// object and its verification report. Version 3 made the report the JSON form
// that every Tinfoil SDK writes (verify.VerificationReport.MarshalJSON), which
// carries its own schema_version, names measurement registers by platform and
// leaves the channel keys in crypto_material only.
const VerificationSchemaVersion = 3

// resultJSON is what Verify returns for a verification that ran: the
// verifier accepted the document, or rejected it with a VerificationError.
// It is the schema of the FFI contract that the Swift and Kotlin SDKs decode.
// The schema is expected to remain stable, to decouple the internal
// implementation details of the Go SDK from the interface that Swift and
// Kotlin see. Avoid changing it if possible.
//
// If it needs non-backwards-compatible modifications, be sure to:
// 1. Bump the VerificationSchemaVersion
// 2. Update the code that decodes it in the tinfoil-swift and tinfoil-kt SDKs
// 3. Update tests/mobile/Smoke.swift and tests/mobile/Smoke.java
//
// The JSON:
//
//	{
//	  "schema_version": 3,
//	  "report": { ...the verification report... },
//	  "error": {"layer": "quote", "message": "verification error: quote: <detail>"}
//	}
//
// report is the verification report in the JSON form that every Tinfoil SDK
// writes, which verify.VerificationReport.MarshalJSON documents. It carries
// its own schema_version, which changes independently of this one; a caller
// checks both. The bridge writes the report unchanged and adds nothing to
// it. Its metadata has no verifier, since this package is built from source
// and so can't name its own version (verify.VerificationMetadata.MarshalJSON):
// the caller records which SDK did the verifying. It has no host either, since
// Verify doesn't know where the document came from: a client that wraps the
// bridge sets metadata.host to the host that it contacted.
//
// On success, error is absent and the report carries verified_facts and no
// partial_facts. On a rejection, error is present, and the report carries
// partial_facts and no verified_facts; the caller throws its verification
// error with the report. A failed step's message is the failing check's
// message, without the "verification error: <layer>: " prefix that
// error.message carries. The channel keys that a caller binds a connection
// to are the verified_facts.crypto_material items with id "tls" and "hpke";
// a TLS-only enclave endorses no HPKE key. The key fingerprints in a
// rejection's partial_facts are only the document's claim, never verified.
type resultJSON struct {
	SchemaVersion int                        `json:"schema_version"`
	Report        *verify.VerificationReport `json:"report"`
	Error         *errorJSON                 `json:"error,omitzero"`
}

// errorJSON is a VerificationError: the layer that rejected the document, and
// the message in the format that errors.go describes.
type errorJSON struct {
	Layer   string `json:"layer"`
	Message string `json:"message"`
}

// toResultJSON maps the outcome of a verification that ran onto the
// contract: report for an accepted document, or rejected for a rejected one.
func toResultJSON(report *verify.VerificationReport, rejected *verify.VerificationError) resultJSON {
	out := resultJSON{SchemaVersion: VerificationSchemaVersion}
	if rejected != nil {
		report = rejected.Report
		out.Error = &errorJSON{Layer: string(rejected.Layer), Message: toMobileError(rejected).Error()}
	}
	// Step messages pass through unchanged: a failed step's is the failing
	// check's message, without the prefix that error.message carries.
	out.Report = report
	return out
}

// measurementJSON is a caller's pinned registers in the options JSON: a type
// and its registers in platform order, in hex, with "" for an unpinned
// register.
type measurementJSON struct {
	Type      string   `json:"type"`
	Registers []string `json:"registers"`
}

// The measurement types of the options JSON.
const (
	sevSNPMeasurementType = "https://tinfoil.sh/predicate/sev-snp-guest/v2"
	tdxMeasurementType    = "https://tinfoil.sh/predicate/tdx-guest/v2"
)

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
