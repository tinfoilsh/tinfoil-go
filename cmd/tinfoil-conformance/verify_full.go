// verify-full subcommand for tinfoil-conformance.
//
// Orchestrates the SPEC §11 end-to-end flow: Sigstore-attested measurement
// (extracted from a signed bundle) cross-checked against a freshly-fetched
// hardware attestation. The conformance binary chains the per-stage entry
// points so that any sub-stage rejection surfaces with its SPEC-anchored
// rejection code AND the sub-stage that produced it.

package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/tinfoilsh/tinfoil-go/verifier/attestation"
	"github.com/tinfoilsh/tinfoil-go/verifier/sigstore"
)

type verifyFullInput struct {
	SchemaVersion       string                      `json:"schema_version"`
	Mode                string                      `json:"mode"`
	Sigstore            *sigstoreSubInput           `json:"sigstore"`
	AttestationSEV      *json.RawMessage            `json:"attestation_sev"`
	AttestationTDX      *json.RawMessage            `json:"attestation_tdx"`
	HardwareMeasurements []hwMeasurementInput       `json:"hardware_measurements"`
	PinnedMeasurement   *measurementInput           `json:"pinned_measurement"`
}

type sigstoreSubInput struct {
	BundleB64               string          `json:"bundle_b64"`
	ExpectedDigestSHA256Hex string          `json:"expected_digest_sha256_hex"`
	Repo                    string          `json:"repo"`
	Policy                  inputPolicy     `json:"policy"`
	TrustRootB64            string          `json:"trust_root_b64"`
	VerificationTimeUnix    json.RawMessage `json:"verification_time_unix"`
}

func emitFullRejection(code, stage, specRef, message string) int {
	body := map[string]any{
		"stage":    "verify-full",
		"accepted": false,
		"rejection": map[string]string{
			"code":     code,
			"stage":    stage,
			"spec_ref": specRef,
			"message":  message,
		},
	}
	out, _ := json.MarshalIndent(body, "", "  ")
	fmt.Println(string(out))
	return exitReject
}

// runSigstoreSub runs the verify-sigstore stage in-process and returns the
// extracted Verification on success.
func runSigstoreSub(in *sigstoreSubInput) (*sigstore.Verification, *struct{ code, specRef, message string }) {
	bundleBytes, err := base64.StdEncoding.DecodeString(in.BundleB64)
	if err != nil {
		return nil, &struct{ code, specRef, message string }{"BUNDLE_MALFORMED", "5.2",
			fmt.Sprintf("bundle_b64 not valid base64: %v", err)}
	}
	trustRootBytes, err := base64.StdEncoding.DecodeString(in.TrustRootB64)
	if err != nil {
		return nil, &struct{ code, specRef, message string }{"TRUST_ROOT_INVALID", "5.1",
			fmt.Sprintf("trust_root_b64 not valid base64: %v", err)}
	}

	policy := &sigstore.Policy{
		OIDCIssuer:                  in.Policy.OIDCIssuer,
		WorkflowRefPrefix:           in.Policy.WorkflowRefPrefix,
		WorkflowRepository:          in.Repo,
		PayloadType:                 in.Policy.PayloadType,
		PredicateTypesAllowed:       nil,
		InTotoStatementTypesAllowed: nil,
	}
	if in.Policy.PredicateTypesAllowed != nil {
		policy.PredicateTypesAllowed = *in.Policy.PredicateTypesAllowed
	} else {
		policy.PredicateTypesAllowed = sigstore.DefaultPolicy(in.Repo).PredicateTypesAllowed
	}
	if in.Policy.InTotoStatementTypesAllowed != nil {
		policy.InTotoStatementTypesAllowed = *in.Policy.InTotoStatementTypesAllowed
	} else {
		policy.InTotoStatementTypesAllowed = sigstore.DefaultPolicy(in.Repo).InTotoStatementTypesAllowed
	}
	if policy.PayloadType == "" {
		policy.PayloadType = "application/vnd.in-toto+json"
	}

	v, err := sigstore.VerifyBundleWithPolicy(bundleBytes, in.ExpectedDigestSHA256Hex, policy, trustRootBytes)
	if err != nil {
		code, specRef := classifyError(err.Error())
		return nil, &struct{ code, specRef, message string }{code, specRef, err.Error()}
	}
	return v, nil
}

// runAttestationSEVSub feeds a raw SEV input through cmdVerifyAttestationSEV's
// pure entrypoint. Returns the parsed measurement on success.
func runAttestationSEVSub(rawInput json.RawMessage) (*attestation.Measurement, *struct{ code, specRef, message string }) {
	var in verifyAttestationSevInput
	if err := json.Unmarshal(rawInput, &in); err != nil {
		return nil, &struct{ code, specRef, message string }{"REPORT_FORMAT_UNSUPPORTED", "3.1",
			fmt.Sprintf("attestation_sev input malformed: %v", err)}
	}
	// Force schema_version so the inner call doesn't reject on missing field.
	in.SchemaVersion = "1"

	parsed, rejErr := runVerifyAttestationSev(&in)
	if rejErr != nil {
		return nil, rejErr
	}
	m := &attestation.Measurement{
		Type:      attestation.SevGuestV2,
		Registers: []string{parsed.MeasurementHex},
	}
	return m, nil
}

func cmdVerifyFull() int {
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading stdin: %v\n", err)
		return exitInternal
	}
	var in verifyFullInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return emitFullRejection("BUNDLE_MALFORMED", "verify-full", "11",
			fmt.Sprintf("input is not valid JSON: %v", err))
	}
	if in.SchemaVersion != "1" {
		return emitFullRejection("BUNDLE_MALFORMED", "verify-full", "11",
			`input.schema_version != "1"`)
	}

	switch in.Mode {
	case "standard", "bundle":
		// Step 1: Sigstore stage
		if in.Sigstore == nil {
			return emitFullRejection("BUNDLE_MALFORMED", "verify-full", "11.1",
				`mode="standard"/"bundle" requires "sigstore" input block`)
		}
		sigV, rej := runSigstoreSub(in.Sigstore)
		if rej != nil {
			return emitFullRejection(rej.code, "verify-sigstore", rej.specRef, rej.message)
		}
		if sigV.Measurement == nil {
			return emitFullRejection("PREDICATE_MEASUREMENT_INVALID", "verify-sigstore", "5.5",
				"sigstore bundle did not yield a measurement")
		}

		// Step 2: Attestation stage (SEV or TDX)
		var attM *attestation.Measurement
		var platform string
		if in.AttestationSEV != nil {
			platform = "sev-snp"
			m, rej := runAttestationSEVSub(*in.AttestationSEV)
			if rej != nil {
				return emitFullRejection(rej.code, "verify-attestation-sev", rej.specRef, rej.message)
			}
			attM = m
		} else if in.AttestationTDX != nil {
			// Wire TDX path when verify-full TDX fixtures land.
			return emitFullRejection("QV_RESULT_TERMINAL_UNSPECIFIED", "verify-full", "11.1",
				"TDX path not yet wired in verify-full Phase 1")
		} else {
			return emitFullRejection("BUNDLE_MALFORMED", "verify-full", "11.1",
				`mode="standard"/"bundle" requires either attestation_sev or attestation_tdx`)
		}

		// Step 3: Cross-stage measurement comparison (SPEC §7.3). The
		// sigstore stage returns a MeasurementOutput; we lift it to the
		// attestation.Measurement type so we can reuse Equals().
		sigPT, ok := parsePredicateType(sigV.Measurement.Type)
		if !ok {
			return emitFullRejection("MEASUREMENT_TYPE_UNKNOWN", "verify-measurement", "2.3",
				fmt.Sprintf("sigstore predicate type %q unknown", sigV.Measurement.Type))
		}
		sigM := &attestation.Measurement{Type: sigPT, Registers: sigV.Measurement.Registers}
		if err := sigM.Equals(attM); err != nil {
			code, specRef := classifyMeasurementError(err)
			return emitFullRejection(code, "verify-measurement", specRef, err.Error())
		}

		// Accept
		fp := fingerprintForOwnType(attM)
		body := map[string]any{
			"stage":    "verify-full",
			"accepted": true,
			"outputs": map[string]any{
				"mode":     in.Mode,
				"platform": platform,
				"sigstore_measurement": map[string]any{
					"type":      sigV.Measurement.Type,
					"registers": sigV.Measurement.Registers,
				},
				"attestation_measurement": map[string]any{
					"type":      attM.Type,
					"registers": attM.Registers,
				},
				"final_measurement_fingerprint_hex": fp,
			},
		}
		out, _ := json.MarshalIndent(body, "", "  ")
		fmt.Println(string(out))
		return exitAccept

	case "pinned":
		if in.PinnedMeasurement == nil {
			return emitFullRejection("BUNDLE_MALFORMED", "verify-full", "11.3",
				`mode="pinned" requires "pinned_measurement"`)
		}
		pinM, code, specRef := normalizeMeasurement(*in.PinnedMeasurement)
		if pinM == nil {
			return emitFullRejection(code, "verify-full", specRef,
				"pinned_measurement invalid")
		}
		if in.AttestationSEV == nil {
			return emitFullRejection("BUNDLE_MALFORMED", "verify-full", "11.3",
				`mode="pinned" requires attestation_sev (TDX not yet wired)`)
		}
		attM, rej := runAttestationSEVSub(*in.AttestationSEV)
		if rej != nil {
			return emitFullRejection(rej.code, "verify-attestation-sev", rej.specRef, rej.message)
		}
		if err := pinM.Equals(attM); err != nil {
			code, specRef := classifyMeasurementError(err)
			return emitFullRejection(code, "verify-measurement", specRef, err.Error())
		}
		fp := fingerprintForOwnType(attM)
		body := map[string]any{
			"stage":    "verify-full",
			"accepted": true,
			"outputs": map[string]any{
				"mode":     in.Mode,
				"platform": "sev-snp",
				"attestation_measurement": map[string]any{
					"type":      attM.Type,
					"registers": attM.Registers,
				},
				"final_measurement_fingerprint_hex": fp,
			},
		}
		out, _ := json.MarshalIndent(body, "", "  ")
		fmt.Println(string(out))
		return exitAccept

	default:
		return emitFullRejection("BUNDLE_MALFORMED", "verify-full", "11",
			fmt.Sprintf("unknown mode %q (allowed: standard, bundle, pinned)", in.Mode))
	}
}
