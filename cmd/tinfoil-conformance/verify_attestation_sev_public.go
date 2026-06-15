package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	sevabi "github.com/google/go-sev-guest/abi"
	"github.com/tinfoilsh/tinfoil-go/verifier/attestation"
)

// cmdVerifyAttestationSEVPublic runs a SEV fixture through the SDK's real
// public verifier entrypoint — attestation.Document.VerifyWithVCEK — instead of
// the lower-level adapter path that assembles google/go-sev-guest primitives
// directly. It hooks only the injected VCEK: the SDK uses its embedded Genoa
// ARK/ASK, so there is no AMD KDS network call. This is the execution_mode=
// public_api path (SPEC §3), used to confirm the report-parse / signature /
// VCEK-chain checks are reachable from the SDK's public surface.
//
// Fixtures that need an injected ARK/ASK, a verification-time override, or
// §3.7 policy pins enforced by the verifier cannot run this way and stay on
// the adapter path (gated by capabilities + the harness's pre-policy filter).
func cmdVerifyAttestationSEVPublic(in *verifyAttestationSevInput) int {
	gzBytes, err := base64.StdEncoding.DecodeString(in.AttestationDocB64)
	if err != nil {
		return emitSevRejection("REPORT_FORMAT_UNSUPPORTED", "3.1",
			fmt.Sprintf("attestation_doc_b64 not valid base64: %v", err))
	}
	reportBytes, err := gunzipBytes(gzBytes)
	if err != nil {
		return emitSevRejection("REPORT_FORMAT_UNSUPPORTED", "3.1",
			fmt.Sprintf("gzip decompress failed: %v", err))
	}
	// Length pre-check keeps REPORT_TRUNCATED distinct from the parser's
	// generic REPORT_FORMAT_UNSUPPORTED, matching the adapter path.
	if len(reportBytes) < 1184 {
		return emitSevRejection("REPORT_TRUNCATED", "3.1",
			fmt.Sprintf("SEV report is %d bytes, expected ≥1184", len(reportBytes)))
	}
	vcekDer, err := base64.StdEncoding.DecodeString(in.VcekDerB64)
	if err != nil {
		return emitSevRejection("VCEK_CHAIN_INVALID", "3.3",
			fmt.Sprintf("vcek_der_b64 not valid base64: %v", err))
	}

	doc, err := attestation.NewDocument(attestation.SevGuestV2, reportBytes)
	if err != nil {
		return emitSevRejection("REPORT_FORMAT_UNSUPPORTED", "3.1",
			fmt.Sprintf("NewDocument failed: %v", err))
	}

	// The SDK's real public verifier: report parse + signature + VCEK chain
	// against the embedded AMD root. Errors funnel through one value; classify
	// against the verify-stage patterns first, then the validate-stage ones
	// (VCEK hwid/tcb cross-checks live in the validate stage).
	if _, err := doc.VerifyWithVCEK(vcekDer); err != nil {
		code, ref := classifySevVerifyError(err)
		if code == "QV_RESULT_TERMINAL_UNSPECIFIED" {
			code, ref = classifySevValidateError(err)
		}
		return emitSevRejection(code, ref, err.Error())
	}

	// Verifier accepted. Decode the body and apply Tinfoil §3.7 policy pins
	// (the public verifier does not enforce caller policy), then emit outputs
	// in the same shape as the adapter accept path.
	parsed, err := sevabi.ReportToProto(reportBytes)
	if err != nil {
		code, ref := classifySevVerifyError(fmt.Errorf("ReportToProto failed: %w", err))
		return emitSevRejection(code, ref, fmt.Sprintf("ReportToProto failed: %v", err))
	}
	if in.Policy != nil {
		if code, ref, msg := enforceSevPolicy(reportBytes, parsed, in.Policy); code != "" {
			return emitSevRejection(code, ref, msg)
		}
	}
	outBody, err := buildSevOutputs(reportBytes, parsed)
	if err != nil {
		return emitSevRejection("QV_RESULT_TERMINAL_UNSPECIFIED", "3",
			fmt.Sprintf("internal: %v", err))
	}
	outputs := outBody["outputs"].(map[string]any)
	bf := outputs["body_fields"].(map[string]any)
	measurement := bf["measurement_hex"].(string)

	body := map[string]any{
		"stage":    "verify-attestation-sev",
		"accepted": true,
		"outputs": map[string]any{
			"measurement": map[string]any{
				"type":      "https://tinfoil.sh/predicate/sev-snp-guest/v2",
				"registers": []string{measurement},
			},
			"body_fields": bf,
		},
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(body)
	return exitAccept
}
