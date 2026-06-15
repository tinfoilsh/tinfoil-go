// tinfoil-conformance is the cross-SDK conformance binary for tinfoil-go.
//
// It speaks the JSON-in / JSON-out CLI contract defined in
// https://github.com/tinfoilsh/tinfoil-conformance. Distinct from the
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
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strings"

	ehbpidentity "github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	"github.com/tinfoilsh/tinfoil-go/verifier/attestation"
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
	case "verify-measurement":
		os.Exit(cmdVerifyMeasurement())
	case "verify-hardware-measurements":
		os.Exit(cmdVerifyHardwareMeasurements())
	case "verify-attestation-tdx":
		os.Exit(cmdVerifyAttestationTDX())
	case "verify-attestation-sev":
		os.Exit(cmdVerifyAttestationSEV())
	case "verify-full":
		os.Exit(cmdVerifyFull())
	case "verify-ehbp-key-binding":
		os.Exit(cmdVerifyEHBPKeyBinding())
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
		"schema_version": "1",
		"sdk":            sdkName,
		"sdk_version":    sdkVersion(),
		"stages_supported": []string{
			"verify-sigstore",
			"verify-measurement",
			"verify-hardware-measurements",
			"verify-attestation-tdx",
			"verify-attestation-sev",
			"verify-full",
			"verify-ehbp-key-binding",
		},
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
		"measurement": map[string]any{
			"compare_multiplatform_to_tdx_supported": true,
		},
		"attestation_sev": map[string]any{
			// Phase 1 wired: cmd/tinfoil-conformance/verify_attestation_sev.go
			// wraps google/go-sev-guest's verify.SnpAttestation with a VCEK
			// cert injected via input.vcek_der_b64.
			"supported":                     true,
			"injected_collateral_supported": true,
			// enforceSevPolicy applies SPEC §3.7 / §3.8 / §8.2-3 pins from
			// policy.expected_*_hex + enforce_spec_defaults.
			"extended_checks_supported":  true,
			"verification_time_override": "supported",
			// input.amd_root_ca_pem + input.ask_pem swap go-sev-guest's
			// TrustedRoots with the fixture's synthetic ARK+ASK chain and
			// set DisableCertFetching=true. Required for Phase 4B-SEV.
			"amd_root_ca_injection_supported": true,
		},
		"attestation_tdx": map[string]any{
			// Phase 1.5 wired: cmd/tinfoil-conformance/verify_attestation_tdx.go
			// wraps google/go-tdx-guest's verify.TdxQuote with an in-process
			// HTTPSGetter that returns fixture-injected collateral, so no
			// network call to Intel PCS happens during conformance runs.
			"supported":                     true,
			"injected_collateral_supported": true,
			// go-tdx-guest's verify.Options.Now is honored end-to-end —
			// cert NotBefore/NotAfter, CRL nextUpdate, JSON nextUpdate
			// all compared against opts.Now from policy.
			"verification_time_override": "supported",
			// CheckRevocations + GetCollateral=true (the tcb_evaluation_
			// required=true path in cmdVerifyAttestationTDX) runs the full
			// §4.7 evaluation: PCK/Root CRL, TCB Info, QE Identity, TCB
			// level matching.
			"tcb_evaluation_supported": true,
			// execution_mode=public_api builds a verifier/attestation.Document
			// and calls the SDK public TDX verification path. The hook API is
			// compiled only into conformance builds with -tags tinfoil_conformance.
			"public_api_hooks_supported": tdxPublicAPIHooksSupported,
			// Phase 4: cmd_verify_attestation_tdx.enforceExtendedPolicy
			// applies SPEC §4.8 / Intel §2.3.2 checks against every
			// policy.expected_*_hex pin the fixture sets.
			"extended_td_checks_supported": true,
			// go-tdx-guest's ErrTcbStatus collapses every non-UpToDate
			// status into a single rejection (strict-only). SPEC §4.7.7
			// would let SWHardeningNeeded etc. through with permissive
			// policy; lib doesn't expose that knob.
			"accepts_non_terminal_tcb_statuses":           false,
			"enforces_tcb_evaluation_data_number_minimum": true,
			"policy_fields_supported": map[string]any{
				"expected_fmspc_hex":  false,
				"accepted_qv_results": false,
			},
		},
		"platforms_supported": []string{"sev-snp", "tdx"},
		// tinfoil-go's client implements both TLS pinning and EHBP
		// (Encrypted HTTP Body Protocol, HPKE) transport. EHBP is now the
		// default transport after the encrypted-transport merge — see
		// ehbp_transport.go and github.com/tinfoilsh/encrypted-http-body-protocol.
		// No fixture gates on transport today; this declares library capability.
		"transport_modes_supported": []string{"tls-pinning", "ehbp"},
		"flow_modes_supported":      []string{"standard", "bundle", "pinned"},
		// SPEC §14.2 EHBP key binding: the transport HPKE key must equal the
		// attested key from report_data[32:64]; a swapped key is rejected.
		// tinfoil-go binds by construction (buildEHBPTransport seals only to
		// the attested key) — see ehbp_transport.go.
		"ehbp": map[string]any{
			"key_binding_supported": true,
		},
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

// -----------------------------------------------------------------------------
// verify-measurement (SPEC §7)
// -----------------------------------------------------------------------------

type measurementInput struct {
	Type      string   `json:"type"`
	Registers []string `json:"registers"`
}

type verifyMeasurementInput struct {
	SchemaVersion string            `json:"schema_version"`
	Source        measurementInput  `json:"source"`
	Target        *measurementInput `json:"target,omitempty"`
}

const (
	sevURI = "https://tinfoil.sh/predicate/sev-snp-guest/v2"
	tdxURI = "https://tinfoil.sh/predicate/tdx-guest/v2"
	mpURI  = "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1"
)

func expectedRegisterCount(t attestation.PredicateType) (int, bool) {
	switch t {
	case attestation.SevGuestV2:
		return 1, true
	case attestation.TdxGuestV2:
		return 5, true
	case attestation.SnpTdxMultiPlatformV1:
		return 3, true
	}
	return 0, false
}

func parsePredicateType(s string) (attestation.PredicateType, bool) {
	switch s {
	case sevURI:
		return attestation.SevGuestV2, true
	case tdxURI:
		return attestation.TdxGuestV2, true
	case mpURI:
		return attestation.SnpTdxMultiPlatformV1, true
	}
	return "", false
}

// normalizeMeasurement validates the predicate type + register count and
// lowercase-normalizes all register values per SPEC §7.3.
func normalizeMeasurement(in measurementInput) (*attestation.Measurement, string, string) {
	t, ok := parsePredicateType(in.Type)
	if !ok {
		return nil, "MEASUREMENT_TYPE_UNKNOWN", "2.3"
	}
	want, _ := expectedRegisterCount(t)
	if len(in.Registers) != want {
		return nil, "MEASUREMENT_REGISTER_COUNT_INVALID", "7.1"
	}
	regs := make([]string, len(in.Registers))
	for i, r := range in.Registers {
		regs[i] = strings.ToLower(r)
	}
	return &attestation.Measurement{Type: t, Registers: regs}, "", ""
}

// fingerprintForOwnType computes the SPEC §7.2 fingerprint of m using its own
// predicate type as the hash prefix. sigstore-gos public attestation.Fingerprint
// helper requires a target type + optional hardware measurement and rejects the
// MP→MP self-fingerprint case; the SPEC defines the formula plainly enough that
// we implement it directly here.
func fingerprintForOwnType(m *attestation.Measurement) string {
	if len(m.Registers) == 1 {
		return m.Registers[0]
	}
	h := sha256.Sum256([]byte(string(m.Type) + strings.Join(m.Registers, "")))
	return fmt.Sprintf("%x", h)
}

func classifyMeasurementError(err error) (string, string) {
	switch {
	case errors.Is(err, attestation.ErrRtmr3Mismatch):
		return "MEASUREMENT_RTMR3_NONZERO", "7.3.2"
	case errors.Is(err, attestation.ErrFewRegisters):
		return "MEASUREMENT_REGISTER_COUNT_INVALID", "7.1"
	case errors.Is(err, attestation.ErrFormatMismatch):
		return "MEASUREMENT_TYPE_COMBINATION_UNSUPPORTED", "7.3.5"
	case errors.Is(err, attestation.ErrRtmr1Mismatch),
		errors.Is(err, attestation.ErrRtmr2Mismatch),
		errors.Is(err, attestation.ErrMultiPlatformMismatch),
		errors.Is(err, attestation.ErrMultiPlatformSevSnpMismatch),
		errors.Is(err, attestation.ErrMeasurementMismatch):
		return "MEASUREMENT_MISMATCH", "7.3"
	}
	low := strings.ToLower(err.Error())
	if strings.Contains(low, "unsupported") || strings.Contains(low, "platform") {
		return "MEASUREMENT_TYPE_COMBINATION_UNSUPPORTED", "7.3.5"
	}
	return "MEASUREMENT_MISMATCH", "7.3"
}

func emitMeasurementRejection(code, specRef, message string) int {
	body := map[string]any{
		"stage":    "verify-measurement",
		"accepted": false,
		"rejection": map[string]string{
			"code":     code,
			"spec_ref": specRef,
			"message":  message,
		},
	}
	out, _ := json.MarshalIndent(body, "", "  ")
	fmt.Println(string(out))
	return exitReject
}

func cmdVerifyMeasurement() int {
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading stdin: %v\n", err)
		return exitInternal
	}
	var in verifyMeasurementInput
	if err := json.Unmarshal(raw, &in); err != nil {
		fmt.Fprintf(os.Stderr, "input schema violation: %v\n", err)
		return exitBadInput
	}
	if in.SchemaVersion != "1" {
		fmt.Fprintln(os.Stderr, "schema_version must be \"1\"")
		return exitBadInput
	}

	src, code, specRef := normalizeMeasurement(in.Source)
	if src == nil {
		return emitMeasurementRejection(code, specRef, "source measurement invalid")
	}
	var tgt *attestation.Measurement
	if in.Target != nil {
		tgt, code, specRef = normalizeMeasurement(*in.Target)
		if tgt == nil {
			return emitMeasurementRejection(code, specRef, "target measurement invalid")
		}
	}

	sourceFP := fingerprintForOwnType(src)
	var targetFP any
	if tgt != nil {
		targetFP = fingerprintForOwnType(tgt)
	} else {
		targetFP = nil
	}

	if tgt != nil {
		if err := src.Equals(tgt); err != nil {
			code, specRef := classifyMeasurementError(err)
			return emitMeasurementRejection(code, specRef, err.Error())
		}
	}

	body := map[string]any{
		"stage":    "verify-measurement",
		"accepted": true,
		"outputs": map[string]any{
			"source_fingerprint_hex": sourceFP,
			"target_fingerprint_hex": targetFP,
		},
	}
	out, _ := json.MarshalIndent(body, "", "  ")
	fmt.Println(string(out))
	return exitAccept
}

// -----------------------------------------------------------------------------
// verify-ehbp-key-binding (SPEC §14.2)
// -----------------------------------------------------------------------------

type ehbpKeyBindingInput struct {
	SchemaVersion           string `json:"schema_version"`
	ReportDataHex           string `json:"report_data_hex"`
	OfferedHPKEPublicKeyHex string `json:"offered_hpke_public_key_hex"`
}

func cmdVerifyEHBPKeyBinding() int {
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading stdin: %v\n", err)
		return exitInternal
	}
	var in ehbpKeyBindingInput
	if err := json.Unmarshal(raw, &in); err != nil {
		fmt.Fprintf(os.Stderr, "input schema violation: %v\n", err)
		return exitBadInput
	}
	if in.SchemaVersion != "1" {
		fmt.Fprintln(os.Stderr, "schema_version must be \"1\"")
		return exitBadInput
	}

	reportData, err := hex.DecodeString(in.ReportDataHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "report_data_hex not valid hex: %v\n", err)
		return exitBadInput
	}
	// Real extraction: report_data[0:32] = TLS fingerprint, [32:64] = HPKE key
	// (SPEC §14.2), via the same slice the verifier applies to a real report.
	tlsFP, attestedHPKE, err := attestation.HPKEKeyFromReportData(reportData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "malformed report_data: %v\n", err)
		return exitBadInput
	}
	// Validate the offered key with the same EHBP key parser the transport
	// uses (ehbp_transport.go buildEHBPTransport -> FromPublicKeyHex).
	if _, err := ehbpidentity.FromPublicKeyHex(in.OfferedHPKEPublicKeyHex); err != nil {
		fmt.Fprintf(os.Stderr, "offered hpke key not a valid X25519 public key: %v\n", err)
		return exitBadInput
	}
	// SPEC §14.2 fail-closed: the offered transport key MUST equal the attested
	// key from report_data[32:64]. tinfoil-go enforces this by construction —
	// it only ever seals to the attested key — so a mismatch is a binding
	// violation.
	if !strings.EqualFold(in.OfferedHPKEPublicKeyHex, attestedHPKE) {
		body := map[string]any{
			"stage":    "verify-ehbp-key-binding",
			"accepted": false,
			"rejection": map[string]string{
				"code":     "EHBP_KEY_BINDING_MISMATCH",
				"spec_ref": "14.2",
				"message":  "offered HPKE key does not match the attested key in report_data[32:64]",
			},
		}
		out, _ := json.MarshalIndent(body, "", "  ")
		fmt.Println(string(out))
		return exitReject
	}

	body := map[string]any{
		"stage":    "verify-ehbp-key-binding",
		"accepted": true,
		"outputs": map[string]any{
			"attested_hpke_public_key_hex": attestedHPKE,
			"tls_fingerprint_hex":          tlsFP,
		},
	}
	out, _ := json.MarshalIndent(body, "", "  ")
	fmt.Println(string(out))
	return exitAccept
}

// -----------------------------------------------------------------------------
// verify-hardware-measurements (SPEC §6)
// -----------------------------------------------------------------------------

type hwMeasurementInput struct {
	ID    string `json:"id"`
	MRTD  string `json:"mrtd"`
	RTMR0 string `json:"rtmr0"`
}

type verifyHardwareInput struct {
	SchemaVersion        string               `json:"schema_version"`
	EnclaveMeasurement   measurementInput     `json:"enclave_measurement"`
	HardwareMeasurements []hwMeasurementInput `json:"hardware_measurements"`
}

func emitHardwareRejection(code, specRef, message string) int {
	body := map[string]any{
		"stage":    "verify-hardware-measurements",
		"accepted": false,
		"rejection": map[string]string{
			"code":     code,
			"spec_ref": specRef,
			"message":  message,
		},
	}
	out, _ := json.MarshalIndent(body, "", "  ")
	fmt.Println(string(out))
	return exitReject
}

func cmdVerifyHardwareMeasurements() int {
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading stdin: %v\n", err)
		return exitInternal
	}
	var in verifyHardwareInput
	if err := json.Unmarshal(raw, &in); err != nil {
		fmt.Fprintf(os.Stderr, "input schema violation: %v\n", err)
		return exitBadInput
	}
	if in.SchemaVersion != "1" {
		fmt.Fprintln(os.Stderr, `schema_version must be "1"`)
		return exitBadInput
	}

	// SPEC §6.3 step 1: enclave_measurement MUST be TdxGuestV2 with exactly 5
	// registers. We validate type + count up-front before consulting the lib's
	// VerifyHardware (which only checks `< 2` registers — a more permissive
	// shape that fixture 221's list-form rejection_code documents).
	if in.EnclaveMeasurement.Type != tdxURI {
		return emitHardwareRejection(
			"ENCLAVE_MEASUREMENT_TYPE_INVALID", "6.3",
			"enclave measurement type is not TdxGuestV2",
		)
	}
	if len(in.EnclaveMeasurement.Registers) != 5 {
		return emitHardwareRejection(
			"ENCLAVE_REGISTER_COUNT_INVALID", "6.3",
			fmt.Sprintf("TDX enclave measurement must have 5 registers, got %d",
				len(in.EnclaveMeasurement.Registers)),
		)
	}

	// SPEC §7.3 lowercase normalization carries over to MRTD/RTMR0 comparisons.
	encRegs := make([]string, len(in.EnclaveMeasurement.Registers))
	for i, r := range in.EnclaveMeasurement.Registers {
		encRegs[i] = strings.ToLower(r)
	}
	hw := make([]*attestation.HardwareMeasurement, len(in.HardwareMeasurements))
	for i, h := range in.HardwareMeasurements {
		hw[i] = &attestation.HardwareMeasurement{
			ID:    h.ID,
			MRTD:  strings.ToLower(h.MRTD),
			RTMR0: strings.ToLower(h.RTMR0),
		}
	}
	enc := &attestation.Measurement{
		Type:      attestation.TdxGuestV2,
		Registers: encRegs,
	}

	match, err := attestation.VerifyHardware(hw, enc)
	if err != nil {
		return emitHardwareRejection("HARDWARE_NO_MATCH", "6.3", err.Error())
	}

	body := map[string]any{
		"stage":    "verify-hardware-measurements",
		"accepted": true,
		"outputs": map[string]any{
			"matched_id":    match.ID,
			"matched_mrtd":  match.MRTD,
			"matched_rtmr0": match.RTMR0,
		},
	}
	out, _ := json.MarshalIndent(body, "", "  ")
	fmt.Println(string(out))
	return exitAccept
}
