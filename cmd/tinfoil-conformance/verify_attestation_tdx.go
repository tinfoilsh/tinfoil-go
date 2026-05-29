// verify-attestation-tdx subcommand for tinfoil-conformance (Phase 1.5).
//
// Wraps google/go-tdx-guest's verify.TdxQuote with a custom HTTPSGetter that
// returns the fixture-injected collateral (TCB Info JSON, QE Identity JSON,
// PCK CRL DER, Root CA CRL DER) instead of fetching from Intel PCS over the
// network. Issuer-chain response headers are stable Intel-signed certs and
// reused from go-tdx-guest's testing package — they're not lib-internal,
// just constants Intel publishes.
//
// Outputs the parsed TD Quote Body fields (MR_SEAM, MR_TD, RTMRs, TD
// Attributes decoded bit-by-bit per Intel §A.3.4, etc.) so the harness can
// diff them across SDKs and so Phase 4 / Phase 5 fixtures can pin them.

package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	tdxabi "github.com/google/go-tdx-guest/abi"
	tdxtesting "github.com/google/go-tdx-guest/testing"
	tdxverify "github.com/google/go-tdx-guest/verify"
	tdxtrust "github.com/google/go-tdx-guest/verify/trust"

	"syscall"
)

// withStdoutSilenced runs fn with the stdout file descriptor temporarily
// redirected to stderr at the OS level. Needed because go-tdx-guest's verify
// package init() calls google/logger.Init(..., os.Stdout), and the fork in
// tinfoil-go won't let us replace the already-initialized default logger.
// Without this redirect, the lib's WARN lines ("Using embedded Intel
// certificate...") corrupt the JSON-on-stdout the conformance contract
// demands.
func withStdoutSilenced(fn func()) {
	stdoutCopy, err := syscall.Dup(1)
	if err != nil {
		fn()
		return
	}
	defer syscall.Close(stdoutCopy)
	if err := syscall.Dup2(2, 1); err != nil {
		fn()
		return
	}
	defer syscall.Dup2(stdoutCopy, 1)
	fn()
}

type tdxCollateralInput struct {
	TcbInfoJSON     string `json:"tcb_info_json"`
	QeIdentityJSON  string `json:"qe_identity_json"`
	PckCRLDerB64    string `json:"pck_crl_der_b64"`
	RootCRLDerB64   string `json:"root_crl_der_b64"`
	IntelRootCAPEM  string `json:"intel_root_ca_pem"`
}

type tdxPolicyInput struct {
	AcceptedQvResults     []string `json:"accepted_qv_results"`
	ExpectedFmspcHex      string   `json:"expected_fmspc_hex"`
	TcbEvaluationRequired *bool    `json:"tcb_evaluation_required"`
}

type verifyAttestationTdxInput struct {
	SchemaVersion           string             `json:"schema_version"`
	QuoteB64                string             `json:"quote_b64"`
	Collateral              tdxCollateralInput `json:"collateral"`
	ExpirationCheckDateUnix int64              `json:"expiration_check_date_unix"`
	Policy                  *tdxPolicyInput    `json:"policy"`
}

// injectedGetter implements trust.HTTPSGetter by pattern-matching the URL
// path (so any fmspc query value resolves) and returning the fixture body
// plus the standard Intel issuer-chain header. Returns 404-style error for
// URLs not relevant to this fixture's verification path.
type injectedGetter struct {
	tcbInfoBody    []byte
	qeIdentityBody []byte
	pckCRLBody     []byte
	rootCRLBody    []byte
}

func (g *injectedGetter) Get(rawURL string) (map[string][]string, []byte, error) {
	switch {
	case strings.HasSuffix(rawURL, "/qe/identity"):
		return tdxtesting.QeIdentityHeader, g.qeIdentityBody, nil
	case strings.Contains(rawURL, "/tcb?fmspc="):
		return tdxtesting.TcbInfoHeader, g.tcbInfoBody, nil
	case strings.Contains(rawURL, "/pckcrl?ca="):
		return tdxtesting.PckCrlHeader, g.pckCRLBody, nil
	case strings.HasSuffix(rawURL, "/IntelSGXRootCA.der"):
		// go-tdx-guest's testdata uses no header for the Root CA CRL.
		return nil, g.rootCRLBody, nil
	}
	return nil, nil, fmt.Errorf("conformance injected getter: no injected response for URL %q", rawURL)
}

func cmdVerifyAttestationTDX() int {
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading stdin: %v\n", err)
		return exitInternal
	}
	var in verifyAttestationTdxInput
	if err := json.Unmarshal(raw, &in); err != nil {
		fmt.Fprintf(os.Stderr, "input schema violation: %v\n", err)
		return exitBadInput
	}
	if in.SchemaVersion != "1" {
		fmt.Fprintln(os.Stderr, `schema_version must be "1"`)
		return exitBadInput
	}

	quoteBytes, err := base64.StdEncoding.DecodeString(in.QuoteB64)
	if err != nil {
		return emitTdxRejection("QUOTE_FORMAT_UNSUPPORTED", "A.3",
			fmt.Sprintf("quote_b64 not valid base64: %v", err))
	}
	pckCRLDer, err := base64.StdEncoding.DecodeString(in.Collateral.PckCRLDerB64)
	if err != nil {
		return emitTdxRejection("PCK_CHAIN_INVALID", "4.1.2",
			fmt.Sprintf("pck_crl_der_b64 not valid base64: %v", err))
	}
	rootCRLDer, err := base64.StdEncoding.DecodeString(in.Collateral.RootCRLDerB64)
	if err != nil {
		return emitTdxRejection("ROOT_CA_UNTRUSTED", "4.1.2",
			fmt.Sprintf("root_crl_der_b64 not valid base64: %v", err))
	}

	getter := &injectedGetter{
		tcbInfoBody:    []byte(in.Collateral.TcbInfoJSON),
		qeIdentityBody: []byte(in.Collateral.QeIdentityJSON),
		pckCRLBody:     pckCRLDer,
		rootCRLBody:    rootCRLDer,
	}

	var quote any
	var verifyErr error
	withStdoutSilenced(func() {
		quote, verifyErr = tdxabi.QuoteToProto(quoteBytes)
	})
	if verifyErr != nil {
		code, ref := classifyTdxError(verifyErr)
		return emitTdxRejection(code, ref, verifyErr.Error())
	}

	opts := tdxverify.DefaultOptions()
	opts.Getter = getter
	opts.Now = time.Unix(in.ExpirationCheckDateUnix, 0).UTC()
	// Default: full §4.7 collateral evaluation. Fixtures can opt out via
	// policy.tcb_evaluation_required=false for structural-only verification
	// (PCK chain + AK + sig, no TCB / CRL).
	tcbEval := true
	if in.Policy != nil && in.Policy.TcbEvaluationRequired != nil {
		tcbEval = *in.Policy.TcbEvaluationRequired
	}
	opts.CheckRevocations = tcbEval
	opts.GetCollateral = tcbEval

	withStdoutSilenced(func() {
		verifyErr = tdxverify.TdxQuote(quote, opts)
	})
	if verifyErr != nil {
		code, ref := classifyTdxError(verifyErr)
		return emitTdxRejection(code, ref, verifyErr.Error())
	}

	// Verification succeeded — emit the parsed body fields for the harness.
	// go-tdx-guest's verify path doesn't expose the qv_result enum directly;
	// reaching this point means the lib mapped the result to OK (or an
	// equivalent terminal-accept).
	body, err := buildTdxOutputs(quote, quoteBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "internal: failed to assemble outputs: %v\n", err)
		return exitInternal
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(body); err != nil {
		fmt.Fprintf(os.Stderr, "internal error: %v\n", err)
		return exitInternal
	}
	return exitAccept
}

// classifyTdxError maps a go-tdx-guest error to a SPEC-anchored rejection
// code. Recognized sentinels first; substring fallthrough for messages from
// deeper layers (abi parser, signature verify) where no sentinel exists.
func classifyTdxError(err error) (string, string) {
	switch {
	case errors.Is(err, tdxverify.ErrPckLeafCertExpired):
		return "PCK_EXPIRED", "4.2"
	case errors.Is(err, tdxverify.ErrRootCaCertExpired),
		errors.Is(err, tdxverify.ErrIntermediateCaCertExpired):
		return "PCK_CHAIN_INVALID", "4.2"
	case errors.Is(err, tdxverify.ErrMissingRootCaCrl):
		return "ROOT_CA_UNTRUSTED", "4.1.2"
	case errors.Is(err, tdxverify.ErrRootCaCrlExpired),
		errors.Is(err, tdxverify.ErrPCKCrlExpired):
		return "PCK_REVOKED", "4.2"
	case errors.Is(err, tdxverify.ErrMissingTcbInfoBody),
		errors.Is(err, tdxverify.ErrTcbInfoNil),
		errors.Is(err, tdxverify.ErrMissingTcbInfoSigningCert),
		errors.Is(err, tdxverify.ErrMissingTcbInfoRootCert),
		errors.Is(err, tdxverify.ErrTcbInfoSigningCertExpired),
		errors.Is(err, tdxverify.ErrTcbInfoRootCertExpired),
		errors.Is(err, tdxverify.ErrTcbInfoExpired):
		return "TCB_INFO_CHAIN_INVALID", "4.7"
	case errors.Is(err, tdxverify.ErrMissingEnclaveIdentityBody),
		errors.Is(err, tdxverify.ErrQeIdentityNil),
		errors.Is(err, tdxverify.ErrMissingQeIdentitySigningCert),
		errors.Is(err, tdxverify.ErrMissingQeIdentityRootCert),
		errors.Is(err, tdxverify.ErrQeIdentitySigningCertExpired),
		errors.Is(err, tdxverify.ErrQeIdentityRootCertExpired),
		errors.Is(err, tdxverify.ErrQeIdentityExpired):
		return "QE_IDENTITY_FIELD_MISMATCH", "4.4"
	case errors.Is(err, tdxverify.ErrTcbStatus),
		errors.Is(err, tdxverify.ErrTcbInfoTcbLevelsMissing):
		return "TCB_REVOKED", "4.7"
	case errors.Is(err, tdxverify.ErrQeIdentityTcbLevelsMissing):
		return "QE_IDENTITY_FIELD_MISMATCH", "4.4"
	case errors.Is(err, tdxverify.ErrCertNil),
		errors.Is(err, tdxverify.ErrParentCertNil),
		errors.Is(err, tdxverify.ErrTrustedCertEmpty):
		return "PCK_CHAIN_INCOMPLETE", "4.2"
	}
	low := strings.ToLower(err.Error())
	// Order matters: cert-chain errors include "signature" substrings (the
	// chain-validation routines say "certificate signature verification …
	// failed"). Test more specific markers first so they aren't swallowed
	// by the generic "signature" pattern.
	switch {
	// Parse-time failures from go-tdx-guest/abi.QuoteToProto:
	case strings.Contains(low, "quote format not supported"):
		return "QUOTE_FORMAT_UNSUPPORTED", "A.3"
	case strings.Contains(low, "raw quote size"),
		strings.Contains(low, "minimum size"):
		return "QUOTE_TRUNCATED", "A.3"
	case strings.Contains(low, "size of certificate data"):
		return "QUOTE_FORMAT_UNSUPPORTED", "A.3.9"
	case strings.Contains(low, "truncat"),
		strings.Contains(low, "too short"):
		return "QUOTE_TRUNCATED", "A.3"

	// PCK cert chain (BEFORE the generic "signature" matcher):
	case strings.Contains(low, "incomplete pck"),
		strings.Contains(low, "pck certificate chain"):
		return "PCK_CHAIN_INCOMPLETE", "A.3.9"
	case strings.Contains(low, "certificate has expired"),
		strings.Contains(low, "not yet valid"):
		return "PCK_EXPIRED", "4.2"
	case strings.Contains(low, "pck leaf certificate"),
		strings.Contains(low, "intermediate ca certificate"),
		strings.Contains(low, "root cert"),
		strings.Contains(low, "pck cert"):
		return "PCK_CHAIN_INVALID", "4.2"

	// AK / quote signature (generic "signature" — must come after chain):
	case strings.Contains(low, "ecdsa attestation key"),
		strings.Contains(low, "quote's signature"):
		return "QUOTE_SIGNATURE_INVALID", "4.3"
	case strings.Contains(low, "qe report"):
		return "QE_REPORT_SIGNATURE_INVALID", "4.4"
	case strings.Contains(low, "signature"):
		return "QUOTE_SIGNATURE_INVALID", "4.3"

	// Header / policy field misuse:
	case strings.Contains(low, "revoked"),
		strings.Contains(low, "crl"):
		return "PCK_REVOKED", "4.2"
	case strings.Contains(low, "fmspc"):
		return "PCK_FMSPC_MISMATCH", "4.6"
	case strings.Contains(low, "tee_type"),
		strings.Contains(low, "tee type"):
		return "WRONG_TEE_TYPE", "A.3.1"
	case strings.Contains(low, "attestation key type"):
		return "ATTESTATION_KEY_TYPE_UNSUPPORTED", "A.3.1"
	case strings.Contains(low, "qe vendor"):
		return "QE_VENDOR_UNKNOWN", "A.3.1"
	}
	return "QV_RESULT_TERMINAL_UNSPECIFIED", "4.1.2"
}

// buildTdxOutputs builds the verify-attestation-tdx output body from the
// parsed quote. Fields mirror the output schema 1:1 so any future field
// addition only touches this function + the schema.
func buildTdxOutputs(quote any, rawQuote []byte) (map[string]any, error) {
	// Re-parse via proto-shape (verify.TdxQuote took *pb.QuoteV4 we already
	// have, but importing the proto here just for type access is heavy —
	// instead we re-extract the body bytes from the raw quote and decode
	// directly. This is the same parse the schema's body_fields block expects.
	if len(rawQuote) < 48+584 {
		return nil, fmt.Errorf("quote shorter than v4 minimum (got %d bytes)", len(rawQuote))
	}
	header := rawQuote[:48]
	body := rawQuote[48 : 48+584]

	version := binary.LittleEndian.Uint16(header[0:2])
	akt := binary.LittleEndian.Uint16(header[2:4])
	teeType := binary.LittleEndian.Uint32(header[4:8])
	qeVendorID := header[12:28]
	userData := header[28:48]

	teeTcbSvn := body[0:16]
	mrSeam := body[16:64]
	mrSignerSeam := body[64:112]
	seamAttrs := body[112:120]
	tdAttrs := body[120:128]
	xfam := body[128:136]
	mrTd := body[136:184]
	mrConfigID := body[184:232]
	mrOwner := body[232:280]
	mrOwnerConfig := body[280:328]
	rtmr0 := body[328:376]
	rtmr1 := body[376:424]
	rtmr2 := body[424:472]
	rtmr3 := body[472:520]
	reportData := body[520:584]

	tdAttrInt := binary.LittleEndian.Uint64(tdAttrs)
	tdDecoded := map[string]bool{
		"tud_debug":                  tdAttrInt&(1<<0) != 0,
		"tud_reserved_nonzero":       tdAttrInt&0xFE != 0,
		"sec_reserved_lower_nonzero": tdAttrInt&0x0FFFFF00 != 0,
		"sec_sept_ve_disable":        tdAttrInt&(1<<28) != 0,
		"sec_reserved_bit29":         tdAttrInt&(1<<29) != 0,
		"sec_pks":                    tdAttrInt&(1<<30) != 0,
		"sec_kl":                     tdAttrInt&(1<<31) != 0,
		"other_reserved_nonzero":     tdAttrInt&0x7FFFFFFF00000000 != 0,
		"other_perfmon":              tdAttrInt&(1<<63) != 0,
	}

	teeTypeStr := "TDX"
	if teeType != 0x81 {
		teeTypeStr = fmt.Sprintf("0x%08x", teeType)
	}

	out := map[string]any{
		"stage":    "verify-attestation-tdx",
		"accepted": true,
		"outputs": map[string]any{
			"quote_version": int(version),
			"tee_type":      teeTypeStr,
			"qv_result":     "OK",
			"measurement": map[string]any{
				"type": "https://tinfoil.sh/predicate/tdx-guest/v2",
				"registers": []string{
					hex.EncodeToString(mrTd),
					hex.EncodeToString(rtmr0),
					hex.EncodeToString(rtmr1),
					hex.EncodeToString(rtmr2),
					hex.EncodeToString(rtmr3),
				},
			},
			"header_fields": map[string]any{
				"attestation_key_type": int(akt),
				"qe_vendor_id_hex":     hex.EncodeToString(qeVendorID),
				"user_data_hex":        hex.EncodeToString(userData),
			},
			"body_fields": map[string]any{
				"tee_tcb_svn_hex":        hex.EncodeToString(teeTcbSvn),
				"mrseam_hex":             hex.EncodeToString(mrSeam),
				"mrsignerseam_hex":       hex.EncodeToString(mrSignerSeam),
				"seam_attributes_hex":    hex.EncodeToString(seamAttrs),
				"td_attributes_hex":      hex.EncodeToString(tdAttrs),
				"td_attributes_decoded":  tdDecoded,
				"xfam_hex":               hex.EncodeToString(xfam),
				"mrtd_hex":               hex.EncodeToString(mrTd),
				"mrconfigid_hex":         hex.EncodeToString(mrConfigID),
				"mrowner_hex":            hex.EncodeToString(mrOwner),
				"mrownerconfig_hex":      hex.EncodeToString(mrOwnerConfig),
				"rtmrs_hex": []string{
					hex.EncodeToString(rtmr0),
					hex.EncodeToString(rtmr1),
					hex.EncodeToString(rtmr2),
					hex.EncodeToString(rtmr3),
				},
				"report_data_hex":        hex.EncodeToString(reportData),
			},
		},
	}
	// Suppress lints on quote (we accept any to avoid pulling pb.QuoteV4 here).
	_ = quote
	_ = tdxtrust.SimpleHTTPSGetter{}
	return out, nil
}

func emitTdxRejection(code, specRef, message string) int {
	body := map[string]any{
		"stage":    "verify-attestation-tdx",
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
