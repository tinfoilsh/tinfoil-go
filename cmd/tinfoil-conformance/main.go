// tinfoil-conformance is the cross-SDK conformance binary for tinfoil-go.
//
// It speaks the JSON-in / JSON-out CLI contract defined in
// https://github.com/lsd-cat/tinfoil-conformance. Distinct from the
// consumer-facing SDK; this is a thin wrapper around verifier/sigstore's
// VerifyBundleWithPolicy entry point.
//
// Subcommands:
//
//	tinfoil-conformance capabilities                # stdin: none, stdout: JSON
//	tinfoil-conformance verify-sigstore             # stdin: JSON, stdout: JSON
//
// Exit codes:
//
//	0   accepted
//	10  rejected (rejection.code populated)
//	20  stage/capability not supported
//	30  malformed input
//	1   internal error
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strings"

	"github.com/tinfoilsh/tinfoil-go/verifier/sigstore"
)

const (
	exitAccept      = 0
	exitReject      = 10
	exitUnsupported = 20
	exitBadInput    = 30
	exitInternal    = 1

	sdkName = "tinfoil-go"
)

func main() {
	args := os.Args[1:]
	sub := ""
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "capabilities":
		os.Exit(cmdCapabilities())
	case "verify-sigstore":
		os.Exit(cmdVerifySigstore())
	case "", "help", "-h", "--help":
		printHelp()
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "tinfoil-conformance: unknown subcommand %q\n", sub)
		printHelp()
		os.Exit(exitBadInput)
	}
}

func printHelp() {
	fmt.Fprintf(os.Stderr,
		"tinfoil-conformance: Tinfoil cross-SDK conformance binary (%s %s)\n\n"+
			"Subcommands:\n"+
			"  capabilities      Print SDK capabilities JSON\n"+
			"  verify-sigstore   Verify a Sigstore bundle (SPEC §5)\n\n"+
			"I/O contract: stdin JSON, stdout JSON. See tinfoil-conformance/schemas/.\n",
		sdkName, sdkVersion(),
	)
}

func sdkVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, m := range info.Deps {
			if m.Path == "github.com/tinfoilsh/tinfoil-go" {
				return m.Version
			}
		}
		return info.Main.Version
	}
	return "0.0.0"
}

func cmdCapabilities() int {
	caps := map[string]any{
		"schema_version":   "1",
		"sdk":              sdkName,
		"sdk_version":      sdkVersion(),
		"stages_supported": []string{"verify-sigstore"},
		"sigstore": map[string]any{
			"trust_root_loading": "configurable",
			// sigstore-go scopes cert validity to bundle-supplied times
			// (cert NotBefore, Rekor integratedTime). The fixture's
			// verification_time_unix isn't currently consulted.
			"verification_time_override": "bundle-supplied-only",
			"policy_fields_configurable": map[string]bool{
				"oidc_issuer":                     true,
				"workflow_ref_prefix":             true,
				"workflow_repository":             true,
				"predicate_types_allowed":         true,
				"in_toto_statement_types_allowed": true,
				// sigstore-go's verifier hardcodes the in-toto payload
				// type at "application/vnd.in-toto+json" inside
				// verify_dsse; not exposed for override.
				"payload_type": false,
				// sigstore-go takes WithSignedCertificateTimestamps(N) and
				// WithTransparencyLog(N) thresholds, but our SDK call
				// hardcodes N=1. Not configurable through the conformance
				// binary today.
				"tlog_entries_min":        false,
				"tlog_entries_max":        false,
				"sct_min":                 false,
				"observer_timestamps_min": false,
			},
			"predicate_types_understood": []string{
				"https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1",
			},
			// v0.3 bundle layout only (sigstore-go's bundle.UnmarshalJSON
			// validates against the protobuf schema).
			"legacy_bundle_format_supported": false,
			// sigstore-go's verifier accepts bundles with multiple tlog
			// entries provided each verifies.
			// sigstore-go accepts multi-tlog bundles in principle but
			// our synthetic shape (each entry in its own size-1 tree)
			// trips the per-entry "logIndex < treeSize" check.
			"accepts_multi_tlog_entries": false,
			// sigstore-go's certificate.ParseExtensions reads .1.8 (V2)
			// when present; falls back to .1.1 (V1).
			"oidc_issuer_v2_preferred": true,
			// sigstore-go counts SCTs (rejects "Expected one SCT, found N")
			// but does NOT have a separate duplicate-log-id check.
			"scts_count_distinguish_missing_vs_duplicate": false,
			// sigstore-go silently accepts a leaf cert carrying two SCTs
			// from the same CT log — no per-log-id uniqueness check.
			"rejects_duplicate_sct_log": false,
			// sigstore-go's WithArtifactDigest iterates ALL subjects and
			// accepts if any matches — diverges from SPEC §5.4's "only
			// subject[0] is checked".
			"checks_only_subject_0": false,
			// sigstore-go's in-toto parser rejects unknown top-level fields
			// on the statement.
			"in_toto_statement_tolerates_extra_fields": false,
		},
		"platforms_supported":       []string{"sev-snp", "tdx"},
		"transport_modes_supported": []string{"tls-pinning", "ehbp"},
		"flow_modes_supported":      []string{"standard"},
		"known_quirks": map[string]any{
			"sigstore.workflow_ref_check_via_extension": "Workflow_ref policy is enforced as a post-verification startsWith() check against the cert's .1.6 extension; sigstore-go's NewShortCertificateIdentity does a SAN regex on BuildSignerURI which is SPEC §5.3-non-canonical.",
		},
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(caps); err != nil {
		fmt.Fprintf(os.Stderr, "internal error: %v\n", err)
		return exitInternal
	}
	return exitAccept
}

type inputPayload struct {
	SchemaVersion           string          `json:"schema_version"`
	BundleB64               string          `json:"bundle_b64"`
	ExpectedDigestSHA256Hex string          `json:"expected_digest_sha256_hex"`
	Repo                    string          `json:"repo"`
	Policy                  inputPolicy     `json:"policy"`
	TrustRootB64            string          `json:"trust_root_b64"`
	VerificationTimeUnix    json.RawMessage `json:"verification_time_unix"`
}

type inputPolicy struct {
	OIDCIssuer                  string    `json:"oidc_issuer"`
	WorkflowRefPrefix           string    `json:"workflow_ref_prefix"`
	PredicateTypesAllowed       *[]string `json:"predicate_types_allowed"`
	InTotoStatementTypesAllowed *[]string `json:"in_toto_statement_types_allowed"`
	PayloadType                 string    `json:"payload_type"`
}

func cmdVerifySigstore() int {
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading stdin: %v\n", err)
		return exitInternal
	}
	var inp inputPayload
	if err := json.Unmarshal(raw, &inp); err != nil {
		return emitRejection("BUNDLE_MALFORMED", "5.2",
			fmt.Sprintf("input is not valid JSON: %v", err), exitBadInput)
	}
	if inp.SchemaVersion != "1" {
		return emitRejection("BUNDLE_MALFORMED", "5.2",
			`input.schema_version != "1"`, exitBadInput)
	}
	bundleBytes, err := base64.StdEncoding.DecodeString(inp.BundleB64)
	if err != nil {
		return emitRejection("BUNDLE_MALFORMED", "5.2",
			fmt.Sprintf("bundle_b64 not valid base64: %v", err), exitBadInput)
	}
	trustRootBytes, err := base64.StdEncoding.DecodeString(inp.TrustRootB64)
	if err != nil {
		return emitRejection("TRUST_ROOT_INVALID", "5.1",
			fmt.Sprintf("trust_root_b64 not valid base64: %v", err), exitBadInput)
	}

	policy := &sigstore.Policy{
		OIDCIssuer:                  inp.Policy.OIDCIssuer,
		WorkflowRefPrefix:           inp.Policy.WorkflowRefPrefix,
		WorkflowRepository:          inp.Repo,
		PayloadType:                 inp.Policy.PayloadType,
		PredicateTypesAllowed:       nil,
		InTotoStatementTypesAllowed: nil,
	}
	if inp.Policy.PredicateTypesAllowed != nil {
		policy.PredicateTypesAllowed = *inp.Policy.PredicateTypesAllowed
	} else {
		policy.PredicateTypesAllowed = sigstore.DefaultPolicy(inp.Repo).PredicateTypesAllowed
	}
	if inp.Policy.InTotoStatementTypesAllowed != nil {
		policy.InTotoStatementTypesAllowed = *inp.Policy.InTotoStatementTypesAllowed
	} else {
		policy.InTotoStatementTypesAllowed = sigstore.DefaultPolicy(inp.Repo).InTotoStatementTypesAllowed
	}
	// PayloadType is non-configurable in our binary (see capabilities); enforce
	// the canonical value if the caller passed something else.
	if policy.PayloadType == "" {
		policy.PayloadType = "application/vnd.in-toto+json"
	}

	v, err := sigstore.VerifyBundleWithPolicy(bundleBytes, inp.ExpectedDigestSHA256Hex, policy, trustRootBytes)
	if err != nil {
		code, specRef := classifyError(err.Error())
		return emitRejection(code, specRef, err.Error(), exitReject)
	}

	// Additional post-check: payload type. (sigstore-go's verifier hardcodes
	// "application/vnd.in-toto+json"; we still emit PAYLOAD_TYPE_MISMATCH
	// here if the caller-supplied policy differs — they'd never have passed
	// verification anyway.)
	if policy.PayloadType != "" && policy.PayloadType != "application/vnd.in-toto+json" {
		return emitRejection("PAYLOAD_TYPE_MISMATCH", "5.4",
			fmt.Sprintf("policy.payload_type=%q is not supported by this SDK; only %q",
				policy.PayloadType, "application/vnd.in-toto+json"),
			exitReject)
	}

	return emitAccept(v)
}

func emitAccept(v *sigstore.Verification) int {
	measurement := map[string]any{}
	if v.Measurement != nil {
		measurement["type"] = v.Measurement.Type
		measurement["registers"] = v.Measurement.Registers
	}
	body := map[string]any{
		"stage":    "verify-sigstore",
		"accepted": true,
		"outputs": map[string]any{
			"predicate_type":             v.PredicateType,
			"in_toto_statement_type":     v.InTotoStatementType,
			"subject_name":               v.SubjectName,
			"subject_digest_sha256_hex":  v.SubjectDigestSHA256Hex,
			"measurement":                measurement,
			"cert_oidc_issuer":           v.CertOIDCIssuer,
			"cert_workflow_repository":   v.CertWorkflowRepository,
			"cert_workflow_signer_uri":   v.CertWorkflowSignerURI,
			"rekor_log_id_hex":           v.RekorLogIDHex,
			"rekor_integrated_time_unix": v.RekorIntegratedTimeUnix,
			"tlog_entry_count":           v.TLogEntryCount,
			"sct_count":                  v.SCTCount,
		},
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(body)
	return exitAccept
}

func emitRejection(code, specRef, message string, exitCode int) int {
	body := map[string]any{
		"stage":    "verify-sigstore",
		"accepted": false,
		"rejection": map[string]any{
			"code":     code,
			"spec_ref": specRef,
			"message":  message,
		},
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(body)
	return exitCode
}

// classifyError maps an error message to the SPEC-anchored rejection-code
// taxonomy. The verifier's policy-driven helpers prefix messages with a
// stable code ("OIDC_ISSUER_MISMATCH:", "WORKFLOW_REF_PREFIX_MISMATCH:", …);
// sigstore-go's own errors come through unprefixed.
func classifyError(msg string) (string, string) {
	// Stable prefixes from VerifyBundleWithPolicy.
	prefixes := []struct {
		prefix, code, specRef string
	}{
		{"TLOG_COUNT_OUT_OF_RANGE:", "TLOG_COUNT_OUT_OF_RANGE", "5.2"},
		{"OIDC_ISSUER_MISMATCH:", "OIDC_ISSUER_MISMATCH", "5.3"},
		{"WORKFLOW_REPOSITORY_MISMATCH:", "WORKFLOW_REPOSITORY_MISMATCH", "5.3"},
		{"WORKFLOW_REF_PREFIX_MISMATCH:", "WORKFLOW_REF_PREFIX_MISMATCH", "5.3"},
		{"PAYLOAD_TYPE_MISMATCH:", "PAYLOAD_TYPE_MISMATCH", "5.4"},
		{"IN_TOTO_STATEMENT_TYPE_NOT_ALLOWED:", "IN_TOTO_STATEMENT_TYPE_NOT_ALLOWED", "5.4"},
		{"PREDICATE_TYPE_NOT_ALLOWED:", "PREDICATE_TYPE_NOT_ALLOWED", "5.5"},
		{"SUBJECT_DIGEST_MISMATCH:", "SUBJECT_DIGEST_MISMATCH", "5.4"},
		{"SUBJECT_MISSING:", "SUBJECT_MISSING", "5.4"},
		{"PREDICATE_MEASUREMENT_INVALID:", "PREDICATE_MEASUREMENT_INVALID", "5.5"},
		{"TRUST_ROOT_INVALID:", "TRUST_ROOT_INVALID", "5.1"},
		{"BUNDLE_MALFORMED:", "BUNDLE_MALFORMED", "5.2"},
	}
	for _, p := range prefixes {
		if strings.Contains(msg, p.prefix) {
			return p.code, p.specRef
		}
	}
	low := strings.ToLower(msg)

	// sigstore-go's certificate-identity check. The "no matching
	// certificateidentity" wrapper text contains the inner cause; check the
	// more specific patterns first so e.g. a workflow-repo mismatch doesn't
	// fall through to the generic OIDC bucket.
	if strings.Contains(low, "githubworkflowrepository") && strings.Contains(low, "expected") {
		return "WORKFLOW_REPOSITORY_MISMATCH", "5.3"
	}
	if strings.Contains(low, "expected issuer value") ||
		(strings.Contains(low, "no matching certificateidentity") && strings.Contains(low, "issuer")) {
		return "OIDC_ISSUER_MISMATCH", "5.3"
	}
	if strings.Contains(low, "no matching certificateidentity") {
		return "OIDC_ISSUER_MISMATCH", "5.3"
	}

	// sigstore-go phrases empty-tlog and missing-rekor-key the same way
	// ("not enough verified log entries from transparency log: 0 < 1").
	if strings.Contains(low, "not enough verified log entries") {
		return "TLOG_COUNT_OUT_OF_RANGE", "5.2"
	}

	// "leaf certificate verification failed" → chain validation failure.
	if strings.Contains(low, "leaf certificate verification failed") {
		return "FULCIO_CHAIN_INVALID", "5.2"
	}

	// sigstore-go's inclusion-proof Merkle reconstruction failure surfaces
	// as "calculated root: [...] does not match observed root: [...]".
	if strings.Contains(low, "calculated root") && strings.Contains(low, "observed root") {
		return "REKOR_INCLUSION_INVALID", "5.2"
	}
	if strings.Contains(low, "calculated root") {
		return "REKOR_INCLUSION_INVALID", "5.2"
	}

	// sigstore-go's `index is beyond size: N >= M` from the multi-entry
	// inclusion check — surface as TLOG_COUNT_OUT_OF_RANGE so the
	// "index beyond size" failure isn't misclassified.
	if strings.Contains(low, "index is beyond size") {
		return "TLOG_COUNT_OUT_OF_RANGE", "5.2"
	}

	// Cert validity vs Rekor integrated time
	if (strings.Contains(low, "outside") && strings.Contains(low, "validity")) ||
		strings.Contains(low, "certificate has expired") || strings.Contains(low, "expired") && strings.Contains(low, "certificate") {
		return "CERT_EXPIRED", "5.2"
	}

	// SCT-related
	if strings.Contains(low, "duplicate") && strings.Contains(low, "sct") {
		return "SCT_DUPLICATE_LOG", "5.2"
	}
	if strings.Contains(low, "sct") && (strings.Contains(low, "no valid") || strings.Contains(low, "missing") || strings.Contains(low, "minimum")) {
		return "SCT_INSUFFICIENT", "5.2"
	}

	// Rekor / tlog
	if strings.Contains(low, "inclusion proof") || strings.Contains(low, "checkpoint") {
		return "REKOR_INCLUSION_INVALID", "5.2"
	}
	if strings.Contains(low, "trusted log key") || strings.Contains(low, "no matching log") || strings.Contains(low, "no log key") {
		return "REKOR_KEY_NOT_TRUSTED", "5.1"
	}
	if strings.Contains(low, "tlog") || strings.Contains(low, "log entry") {
		return "TLOG_COUNT_OUT_OF_RANGE", "5.2"
	}

	if strings.Contains(low, "trust root") || strings.Contains(low, "trusted root") {
		return "TRUST_ROOT_INVALID", "5.1"
	}
	if strings.Contains(low, "fulcio") || strings.Contains(low, "certificate chain") || strings.Contains(low, "no valid ca") {
		return "FULCIO_CHAIN_INVALID", "5.2"
	}
	if strings.Contains(low, "signature") && (strings.Contains(low, "invalid") || strings.Contains(low, "verification") || strings.Contains(low, "failed")) {
		return "DSSE_SIGNATURE_INVALID", "5.2"
	}
	return "BUNDLE_MALFORMED", "5.2"
}
