// verify-attestation-sev subcommand for tinfoil-conformance.
//
// Wraps google/go-sev-guest's verify.SnpAttestation. Input is the gzipped
// SEV-SNP attestation doc + VCEK DER cert; output is the parsed body fields
// + measurement.

package main

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"

	sevabi "github.com/google/go-sev-guest/abi"
	sevkds "github.com/google/go-sev-guest/kds"
	sevpb "github.com/google/go-sev-guest/proto/sevsnp"
	sevtrust "github.com/google/go-sev-guest/verify/trust"
	sevvalidate "github.com/google/go-sev-guest/validate"
	sevverify "github.com/google/go-sev-guest/verify"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

//go:embed genoa_cert_chain.pem
var embeddedGenoaCertChain []byte

// embeddedChainGetter serves the embedded Genoa ARK||ASK PEM bundle for any
// `/cert_chain` URL; other URLs (VCEK fetches) are rejected — the conformance
// binary always receives the VCEK inline so it must never escape to the network.
type embeddedChainGetter struct {
	chain []byte
}

func (g *embeddedChainGetter) Get(target string) ([]byte, error) {
	u, err := url.Parse(target)
	if err != nil {
		return nil, err
	}
	if strings.HasSuffix(u.Path, "/cert_chain") {
		return g.chain, nil
	}
	return nil, fmt.Errorf("conformance binary forbids network fetch of %s — VCEK must be inline", target)
}

type sevPolicyInput struct {
	ExpectedMeasurementHex     string `json:"expected_measurement_hex"`
	ExpectedHostDataHex        string `json:"expected_host_data_hex"`
	ExpectedReportDataHex      string `json:"expected_report_data_hex"`
	ExpectedIdKeyDigestHex     string `json:"expected_id_key_digest_hex"`
	ExpectedAuthorKeyDigestHex string `json:"expected_author_key_digest_hex"`
	MinTcbBlSpl                *int   `json:"min_tcb_bl_spl"`
	MinTcbTeeSpl               *int   `json:"min_tcb_tee_spl"`
	MinTcbSnpSpl               *int   `json:"min_tcb_snp_spl"`
	MinTcbUcodeSpl             *int   `json:"min_tcb_ucode_spl"`
	EnforceSpecDefaults        bool   `json:"enforce_spec_defaults"`
}

type verifyAttestationSevInput struct {
	SchemaVersion            string         `json:"schema_version"`
	AttestationDocB64        string         `json:"attestation_doc_b64"`
	VcekDerB64               string         `json:"vcek_der_b64"`
	AmdRootCAPEM             string         `json:"amd_root_ca_pem"`
	AskPEM                   string         `json:"ask_pem"`
	ExpirationCheckDateUnix  int64          `json:"expiration_check_date_unix"`
	Policy                   *sevPolicyInput `json:"policy"`
	ExecutionMode            string         `json:"execution_mode"`
}

func gunzipBytes(in []byte) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(in))
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	return io.ReadAll(gz)
}

// sevParsedOutput is the data verify-full needs from a successful SEV
// verification: the parsed report bytes plus the decoded body fields.
type sevParsedOutput struct {
	ReportBytes    []byte
	MeasurementHex string
	BodyFields     map[string]any
}

type sevRejection struct {
	code, specRef, message string
}

// runVerifyAttestationSev is the pure entry point: takes parsed input,
// returns either a successful parse + verify or a rejection. Shared by
// cmdVerifyAttestationSEV (stdin/stdout wrapper) and runAttestationSEVSub
// (verify-full chaining).
func runVerifyAttestationSev(in *verifyAttestationSevInput) (*sevParsedOutput, *struct{ code, specRef, message string }) {
	gzBytes, err := base64.StdEncoding.DecodeString(in.AttestationDocB64)
	if err != nil {
		return nil, &struct{ code, specRef, message string }{"REPORT_FORMAT_UNSUPPORTED", "3.1",
			fmt.Sprintf("attestation_doc_b64 not valid base64: %v", err)}
	}
	reportBytes, err := gunzipBytes(gzBytes)
	if err != nil {
		return nil, &struct{ code, specRef, message string }{"REPORT_FORMAT_UNSUPPORTED", "3.1",
			fmt.Sprintf("gzip decompress failed: %v", err)}
	}
	if len(reportBytes) < 1184 {
		return nil, &struct{ code, specRef, message string }{"REPORT_TRUNCATED", "3.1",
			fmt.Sprintf("SEV report is %d bytes, expected ≥1184", len(reportBytes))}
	}

	vcekDer, err := base64.StdEncoding.DecodeString(in.VcekDerB64)
	if err != nil {
		return nil, &struct{ code, specRef, message string }{"VCEK_CHAIN_INVALID", "3.3",
			fmt.Sprintf("vcek_der_b64 not valid base64: %v", err)}
	}

	parsed, err := sevabi.ReportToProto(reportBytes)
	if err != nil {
		// go-sev-guest's parser enforces SPEC §3.2.2 guest_policy MBO/MBZ
		// constraints inline. Route the error through classifySevVerifyError
		// so a "malformed guest policy" failure lands on
		// GUEST_POLICY_RESERVED_BIT_SET rather than the generic
		// REPORT_FORMAT_UNSUPPORTED bucket.
		code, ref := classifySevVerifyError(fmt.Errorf("ReportToProto failed: %w", err))
		return nil, &struct{ code, specRef, message string }{code, ref,
			fmt.Sprintf("ReportToProto failed: %v", err)}
	}

	attestation := &sevpb.Attestation{
		Report: parsed,
		CertificateChain: &sevpb.CertificateChain{
			VcekCert: vcekDer,
		},
		Product: &sevpb.SevProduct{
			Name:            sevpb.SevProduct_SEV_PRODUCT_GENOA,
			MachineStepping: &wrapperspb.UInt32Value{Value: 0},
		},
	}

	opts := sevverify.DefaultOptions()
	opts.Product = attestation.Product
	if in.ExpirationCheckDateUnix > 0 {
		opts.Now = time.Unix(in.ExpirationCheckDateUnix, 0).UTC()
	}
	if in.AmdRootCAPEM != "" && in.AskPEM != "" {
		chain := strings.TrimSpace(in.AskPEM) + "\n" + strings.TrimSpace(in.AmdRootCAPEM) + "\n"
		root := sevtrust.AMDRootCertsProduct("Genoa")
		if err := root.FromKDSCertBytes([]byte(chain)); err != nil {
			return nil, &struct{ code, specRef, message string }{"ARK_UNTRUSTED", "3.3.1",
				fmt.Sprintf("could not parse fixture-supplied AMD chain: %v", err)}
		}
		opts.TrustedRoots = map[string][]*sevtrust.AMDRootCerts{"Genoa": {root}}
		opts.DisableCertFetching = true
	} else {
		opts.Getter = &embeddedChainGetter{chain: embeddedGenoaCertChain}
	}

	if err := sevverify.SnpAttestation(attestation, opts); err != nil {
		code, ref := classifySevVerifyError(err)
		return nil, &struct{ code, specRef, message string }{code, ref, err.Error()}
	}

	valOpts := &sevvalidate.Options{
		GuestPolicy: sevabi.SnpPolicy{
			SMT: true, MigrateMA: false, Debug: false, SingleSocket: false,
		},
		PermitProvisionalFirmware: true,
	}
	if err := sevvalidate.SnpAttestation(attestation, valOpts); err != nil {
		code, ref := classifySevValidateError(err)
		return nil, &struct{ code, specRef, message string }{code, ref, err.Error()}
	}

	if in.Policy != nil {
		if code, ref, msg := enforceSevPolicy(reportBytes, parsed, in.Policy); code != "" {
			return nil, &struct{ code, specRef, message string }{code, ref, msg}
		}
	}

	body, err := buildSevOutputs(reportBytes, parsed)
	if err != nil {
		return nil, &struct{ code, specRef, message string }{"QV_RESULT_TERMINAL_UNSPECIFIED", "3",
			fmt.Sprintf("internal: %v", err)}
	}
	outputs := body["outputs"].(map[string]any)
	bf := outputs["body_fields"].(map[string]any)
	measurement := bf["measurement_hex"].(string)
	return &sevParsedOutput{
		ReportBytes:    reportBytes,
		MeasurementHex: measurement,
		BodyFields:     bf,
	}, nil
}

func cmdVerifyAttestationSEV() int {
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading stdin: %v\n", err)
		return exitInternal
	}
	var in verifyAttestationSevInput
	if err := json.Unmarshal(raw, &in); err != nil {
		fmt.Fprintf(os.Stderr, "input schema violation: %v\n", err)
		return exitBadInput
	}
	if in.SchemaVersion != "1" {
		fmt.Fprintln(os.Stderr, `schema_version must be "1"`)
		return exitBadInput
	}

	if in.ExecutionMode == "public_api" {
		return cmdVerifyAttestationSEVPublic(&in)
	}

	parsed, rej := runVerifyAttestationSev(&in)
	if rej != nil {
		return emitSevRejection(rej.code, rej.specRef, rej.message)
	}

	body := map[string]any{
		"stage":    "verify-attestation-sev",
		"accepted": true,
		"outputs": map[string]any{
			"measurement": map[string]any{
				"type":      "https://tinfoil.sh/predicate/sev-snp-guest/v2",
				"registers": []string{parsed.MeasurementHex},
			},
			"body_fields": parsed.BodyFields,
		},
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(body); err != nil {
		fmt.Fprintf(os.Stderr, "internal: %v\n", err)
		return exitInternal
	}
	return exitAccept
}

func classifySevVerifyError(err error) (string, string) {
	low := strings.ToLower(err.Error())
	// Order matters: specific patterns first; the "trusted roots" wrapper
	// message contains "root" and must not fall through to ARK_UNTRUSTED.
	switch {
	case strings.Contains(low, "expired") || strings.Contains(low, "not yet valid"):
		return "VCEK_EXPIRED", "3.3.3"
	case strings.Contains(low, "vcek") && strings.Contains(low, "hwid"),
		strings.Contains(low, "chip_id") && strings.Contains(low, "does not match"),
		strings.Contains(low, "missing hwid"):
		return "VCEK_HWID_MISMATCH", "3.4.4"
	// go-sev-guest's TCB-vs-cert message phrases the cert side as "V[CL]EK
	// certificate" — lowercased it's "v[cl]ek" which doesn't contain "vcek".
	// Match the "reported_tcb does not match" phrase directly.
	case strings.Contains(low, "vcek") && strings.Contains(low, "tcb"),
		strings.Contains(low, "reported_tcb") && strings.Contains(low, "does not match"),
		strings.Contains(low, "v[cl]ek") && strings.Contains(low, "tcb"):
		return "VCEK_TCB_MISMATCH", "3.4.3"
	// go-sev-guest emits "VCEK could not be verified by any trusted roots"
	// for a broken ASK→VCEK chain (and also wraps "certificate signed by
	// unknown authority"). Treat as VCEK_CHAIN_INVALID — distinct from
	// "ARK itself is not trusted", which we surface only when a fixture
	// explicitly swaps the ARK below.
	case strings.Contains(low, "vcek") && strings.Contains(low, "could not be verified"):
		return "VCEK_CHAIN_INVALID", "3.3.5"
	case strings.Contains(low, "malformed certificate"),
		strings.Contains(low, "could not interpret vcek"),
		strings.Contains(low, "asn1") && strings.Contains(low, "vcek"),
		strings.Contains(low, "vcek") && strings.Contains(low, "chain"):
		return "VCEK_CHAIN_INVALID", "3.3.5"
	case strings.Contains(low, "ark"):
		return "ARK_UNTRUSTED", "3.3.1"
	case strings.Contains(low, "ask"):
		return "ASK_INVALID", "3.3.2"
	case strings.Contains(low, "signature"):
		return "REPORT_SIGNATURE_INVALID", "3.6"
	// go-sev-guest's parser enforces SPEC §3.2.2 guest_policy MBO/MBZ
	// constraints at ReportToProto time — surfaces as
	// "malformed guest policy: policy[17] is reserved, must be 1, got 0"
	// or "malformed guest policy: mbz range policy[0x19:0x3f] not all zero".
	case strings.Contains(low, "guest policy") &&
		(strings.Contains(low, "reserved") || strings.Contains(low, "mbz") || strings.Contains(low, "must be")):
		return "GUEST_POLICY_RESERVED_BIT_SET", "3.2.2"
	case strings.Contains(low, "format"),
		strings.Contains(low, "parse"),
		strings.Contains(low, "mbz"),
		strings.Contains(low, "reporttoproto"):
		return "REPORT_FORMAT_UNSUPPORTED", "3.1"
	}
	return "QV_RESULT_TERMINAL_UNSPECIFIED", "3"
}

func classifySevValidateError(err error) (string, string) {
	low := strings.ToLower(err.Error())
	switch {
	// VCEK §3.4 cross-checks happen inside validate.SnpAttestation, not
	// verify.SnpAttestation. Catch them before the generic "tcb" bucket.
	case strings.Contains(low, "chip_id") && (strings.Contains(low, "is not the same") ||
		strings.Contains(low, "does not match")),
		strings.Contains(low, "hwid") && (strings.Contains(low, "is not the same") ||
			strings.Contains(low, "does not match")):
		return "VCEK_HWID_MISMATCH", "3.4.4"
	case (strings.Contains(low, "reported_tcb") && strings.Contains(low, "does not match")) ||
		(strings.Contains(low, "v[cl]ek") && strings.Contains(low, "tcb")):
		return "VCEK_TCB_MISMATCH", "3.4.3"
	case strings.Contains(low, "debug"):
		return "GUEST_POLICY_DEBUG_SET", "3.7"
	case strings.Contains(low, "migration") || strings.Contains(low, "migrate"):
		return "GUEST_POLICY_MIGRATE_MA_SET", "3.7"
	case strings.Contains(low, "single") && strings.Contains(low, "socket"):
		return "GUEST_POLICY_SINGLE_SOCKET_SET", "3.7"
	case strings.Contains(low, "tcb"):
		return "TCB_OUT_OF_DATE", "3.7"
	case strings.Contains(low, "platform"):
		return "PLATFORM_INFO_INVALID", "3.7"
	case strings.Contains(low, "signer"):
		return "SIGNER_INFO_INVALID", "3.7"
	}
	return "QV_RESULT_TERMINAL_UNSPECIFIED", "3.7"
}

func enforceSevPolicy(rawReport []byte, parsed *sevpb.Report, p *sevPolicyInput) (string, string, string) {
	// SPEC §3.1.1 field offsets in the SEV-SNP report.
	measurement := rawReport[0x90 : 0x90+48]
	hostData := rawReport[0xC0 : 0xC0+32]
	idKeyDigest := rawReport[0xE0 : 0xE0+48]
	authorKeyDigest := rawReport[0x110 : 0x110+48]
	reportData := rawReport[0x50 : 0x50+64]
	policy := binary.LittleEndian.Uint64(rawReport[0x08:0x10])
	platformInfo := binary.LittleEndian.Uint64(rawReport[0x188:0x190])

	matchHex := func(expected string, got []byte) bool {
		if expected == "" {
			return true
		}
		exp, err := hex.DecodeString(strings.ToLower(strings.TrimSpace(expected)))
		if err != nil || len(exp) != len(got) {
			return false
		}
		return bytes.Equal(exp, got)
	}

	if !matchHex(p.ExpectedMeasurementHex, measurement) {
		return "MEASUREMENT_MISMATCH", "3.8", fmt.Sprintf(
			"measurement %s != policy expected %s",
			hex.EncodeToString(measurement), strings.ToLower(p.ExpectedMeasurementHex))
	}
	if !matchHex(p.ExpectedHostDataHex, hostData) {
		return "HOST_DATA_MISMATCH", "8.3", fmt.Sprintf(
			"host_data %s != policy expected %s",
			hex.EncodeToString(hostData), strings.ToLower(p.ExpectedHostDataHex))
	}
	if !matchHex(p.ExpectedReportDataHex, reportData) {
		return "REPORT_DATA_MISMATCH", "8.2", fmt.Sprintf(
			"report_data %s != policy expected %s",
			hex.EncodeToString(reportData), strings.ToLower(p.ExpectedReportDataHex))
	}
	if !matchHex(p.ExpectedIdKeyDigestHex, idKeyDigest) {
		return "ID_KEY_DIGEST_MISMATCH", "3.1.1", fmt.Sprintf(
			"id_key_digest %s != policy expected %s",
			hex.EncodeToString(idKeyDigest), strings.ToLower(p.ExpectedIdKeyDigestHex))
	}
	if !matchHex(p.ExpectedAuthorKeyDigestHex, authorKeyDigest) {
		return "AUTHOR_KEY_DIGEST_MISMATCH", "3.1.1", fmt.Sprintf(
			"author_key_digest %s != policy expected %s",
			hex.EncodeToString(authorKeyDigest), strings.ToLower(p.ExpectedAuthorKeyDigestHex))
	}

	if p.EnforceSpecDefaults {
		// §3.2.2 guest policy: bit 19 = DEBUG; bit 20 = SINGLE_SOCKET.
		const DEBUG_BIT uint64 = 1 << 19
		if policy&DEBUG_BIT != 0 {
			return "GUEST_POLICY_DEBUG_SET", "3.7", fmt.Sprintf(
				"guest_policy DEBUG bit (19) is set (policy=%016x)", policy)
		}
		// §3.2.2 / AMD APM Vol 3 Table B-3: bit 17 is reserved-MBO (must
		// be 1); bits 25-63 are reserved-MBZ (must be 0). Real SEV uses
		// bits 0-7 (abi minor), 8-15 (abi major), 16 (smt), 17 (rsv-MBO),
		// 18 (migrate_ma), 19 (debug), 20 (single_socket), 21 (cxl),
		// 22 (mem_aes), 23 (rapl_dis), 24 (ciphertext_hiding_dram).
		const RESERVED_MBO_BIT uint64 = 1 << 17
		if policy&RESERVED_MBO_BIT == 0 {
			return "GUEST_POLICY_RESERVED_BIT_SET", "3.7", fmt.Sprintf(
				"guest_policy reserved-MBO bit (17) is clear (policy=%016x)", policy)
		}
		const RESERVED_MBZ_MASK uint64 = 0xFFFFFFFFFE000000
		if policy&RESERVED_MBZ_MASK != 0 {
			return "GUEST_POLICY_RESERVED_BIT_SET", "3.7", fmt.Sprintf(
				"guest_policy has reserved-MBZ bit(s) (≥25) set (policy=%016x)", policy)
		}
		_ = platformInfo
	}

	// TCB minimums (§3.7). Optional fields; only enforced when set.
	currentTcb := binary.LittleEndian.Uint64(rawReport[0x180:0x188])
	tcb := sevkds.DecomposeTCBVersion(sevkds.TCBVersion(currentTcb))
	if p.MinTcbBlSpl != nil && int(tcb.BlSpl) < *p.MinTcbBlSpl {
		return "TCB_OUT_OF_DATE", "3.7", fmt.Sprintf(
			"tcb.bl_spl=%d below minimum %d", tcb.BlSpl, *p.MinTcbBlSpl)
	}
	if p.MinTcbTeeSpl != nil && int(tcb.TeeSpl) < *p.MinTcbTeeSpl {
		return "TCB_OUT_OF_DATE", "3.7", fmt.Sprintf(
			"tcb.tee_spl=%d below minimum %d", tcb.TeeSpl, *p.MinTcbTeeSpl)
	}
	if p.MinTcbSnpSpl != nil && int(tcb.SnpSpl) < *p.MinTcbSnpSpl {
		return "TCB_OUT_OF_DATE", "3.7", fmt.Sprintf(
			"tcb.snp_spl=%d below minimum %d", tcb.SnpSpl, *p.MinTcbSnpSpl)
	}
	if p.MinTcbUcodeSpl != nil && int(tcb.UcodeSpl) < *p.MinTcbUcodeSpl {
		return "TCB_OUT_OF_DATE", "3.7", fmt.Sprintf(
			"tcb.ucode_spl=%d below minimum %d", tcb.UcodeSpl, *p.MinTcbUcodeSpl)
	}
	_ = parsed
	return "", "", ""
}

func buildSevOutputs(rawReport []byte, parsed *sevpb.Report) (map[string]any, error) {
	if len(rawReport) < 1184 {
		return nil, fmt.Errorf("report too short")
	}
	version := binary.LittleEndian.Uint32(rawReport[0x00:0x04])
	guestSvn := binary.LittleEndian.Uint32(rawReport[0x04:0x08])
	policy := binary.LittleEndian.Uint64(rawReport[0x08:0x10])
	familyId := rawReport[0x10:0x20]
	imageId := rawReport[0x20:0x30]
	vmpl := binary.LittleEndian.Uint32(rawReport[0x30:0x34])
	signatureAlgo := binary.LittleEndian.Uint32(rawReport[0x34:0x38])
	currentTcb := binary.LittleEndian.Uint64(rawReport[0x38:0x40])
	platformInfo := binary.LittleEndian.Uint64(rawReport[0x40:0x48])
	signerInfo := binary.LittleEndian.Uint32(rawReport[0x48:0x4C])
	reportData := rawReport[0x50:0x90]
	measurement := rawReport[0x90 : 0x90+48]
	hostData := rawReport[0xC0 : 0xC0+32]
	idKeyDigest := rawReport[0xE0 : 0xE0+48]
	authorKeyDigest := rawReport[0x110 : 0x110+48]
	reportId := rawReport[0x140 : 0x140+32]
	reportIdMa := rawReport[0x160 : 0x160+32]
	reportedTcb := rawReport[0x180 : 0x180+8]
	chipId := rawReport[0x1A0 : 0x1A0+64]
	committedTcb := rawReport[0x1E8 : 0x1E8+8]
	currentBuild := uint16(rawReport[0x1F0])
	currentMinor := uint16(rawReport[0x1F1])
	currentMajor := uint16(rawReport[0x1F2])
	committedBuild := uint16(rawReport[0x1F4])
	committedMinor := uint16(rawReport[0x1F5])
	committedMajor := uint16(rawReport[0x1F6])
	launchTcb := rawReport[0x1F8 : 0x1F8+8]

	// SPEC §3.2.2 / AMD APM Vol 3 Table B-3. Bit 17 is reserved-MBO; the
	// post-MBO flags start at bit 18 (MIGRATE_MA), not 17.
	policyDecoded := map[string]any{
		"abi_minor":              policy & 0xff,
		"abi_major":              (policy >> 8) & 0xff,
		"smt":                    policy&(1<<16) != 0,
		"reserved_mbo":           policy&(1<<17) != 0,
		"migrate_ma":             policy&(1<<18) != 0,
		"debug":                  policy&(1<<19) != 0,
		"single_socket":          policy&(1<<20) != 0,
		"cxl_allow":              policy&(1<<21) != 0,
		"mem_aes_256_xts":        policy&(1<<22) != 0,
		"raplmsr_dis":            policy&(1<<23) != 0,
		"ciphertext_hiding_dram": policy&(1<<24) != 0,
	}
	platformInfoDecoded := map[string]any{
		"smt_en":            platformInfo&(1<<0) != 0,
		"tsme_en":           platformInfo&(1<<1) != 0,
		"ecc_en":            platformInfo&(1<<2) != 0,
		"rapl_dis":          platformInfo&(1<<3) != 0,
		"ciphertext_hiding": platformInfo&(1<<4) != 0,
	}
	currentTcbDecoded := map[string]any{
		"bl_spl":    int(currentTcb & 0xff),
		"tee_spl":   int((currentTcb >> 8) & 0xff),
		"snp_spl":   int((currentTcb >> 48) & 0xff),
		"ucode_spl": int((currentTcb >> 56) & 0xff),
	}

	_ = parsed
	return map[string]any{
		"stage":    "verify-attestation-sev",
		"accepted": true,
		"outputs": map[string]any{
			"measurement": map[string]any{
				"type":      "https://tinfoil.sh/predicate/sev-snp-guest/v2",
				"registers": []string{hex.EncodeToString(measurement)},
			},
			"body_fields": map[string]any{
				"version":              int(version),
				"guest_svn":            int(guestSvn),
				"policy_hex":           fmt.Sprintf("%016x", policy),
				"policy_decoded":       policyDecoded,
				"family_id_hex":        hex.EncodeToString(familyId),
				"image_id_hex":         hex.EncodeToString(imageId),
				"vmpl":                 int(vmpl),
				"signature_algo":       int(signatureAlgo),
				"current_tcb_hex":      fmt.Sprintf("%016x", currentTcb),
				"current_tcb_decoded":  currentTcbDecoded,
				"platform_info_hex":    fmt.Sprintf("%016x", platformInfo),
				"platform_info_decoded": platformInfoDecoded,
				"signer_info_hex":      fmt.Sprintf("%08x", signerInfo),
				"report_data_hex":      hex.EncodeToString(reportData),
				"measurement_hex":      hex.EncodeToString(measurement),
				"host_data_hex":        hex.EncodeToString(hostData),
				"id_key_digest_hex":    hex.EncodeToString(idKeyDigest),
				"author_key_digest_hex": hex.EncodeToString(authorKeyDigest),
				"report_id_hex":        hex.EncodeToString(reportId),
				"report_id_ma_hex":     hex.EncodeToString(reportIdMa),
				"reported_tcb_hex":     hex.EncodeToString(reportedTcb),
				"chip_id_hex":          hex.EncodeToString(chipId),
				"committed_tcb_hex":    hex.EncodeToString(committedTcb),
				"current_build":        int(currentBuild),
				"current_minor":        int(currentMinor),
				"current_major":        int(currentMajor),
				"committed_build":      int(committedBuild),
				"committed_minor":      int(committedMinor),
				"committed_major":      int(committedMajor),
				"launch_tcb_hex":       hex.EncodeToString(launchTcb),
			},
		},
	}, nil
}

func emitSevRejection(code, specRef, message string) int {
	body := map[string]any{
		"stage":    "verify-attestation-sev",
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
