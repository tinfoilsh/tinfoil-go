package sigstore

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"google.golang.org/protobuf/types/known/structpb"
)

// VerifyBundleWithPolicy is the mid-level entry point that the cross-SDK
// conformance binary calls. It mirrors verify_bundle_with_policy in
// tinfoil-rs, verifySigstoreBundleWithPolicy in tinfoil-js, and
// verify_sigstore_bundle_with_policy in tinfoil-python. No network I/O:
// bundle bytes, expected digest, policy, and trust root are all caller-
// supplied.
//
// The workflow_ref policy check is performed against the cert's
// GitHubWorkflowRef extension (OID 1.3.6.1.4.1.57264.1.6) via a post-
// verification prefix match — sigstore-go's NewShortCertificateIdentity
// only takes a regex on the SAN/BuildSignerURI, which is not the SPEC §5.3
// source of truth. We use NewCertificateIdentity instead so we can pin the
// GithubWorkflowRepository extension exactly, then check the workflow_ref
// extension's prefix ourselves.
func VerifyBundleWithPolicy(
	bundleJSON []byte,
	expectedDigest string,
	policy *Policy,
	trustRootJSON []byte,
) (*Verification, error) {
	trustRoot, err := root.NewTrustedRootFromJSON(trustRootJSON)
	if err != nil {
		return nil, fmt.Errorf("TRUST_ROOT_INVALID: parsing trust root: %w", err)
	}

	var b bundle.Bundle
	b.Bundle = new(protobundle.Bundle)
	if err := b.UnmarshalJSON(bundleJSON); err != nil {
		return nil, fmt.Errorf("BUNDLE_MALFORMED: parsing bundle: %w", err)
	}
	if err := rejectLegacyBundleFormat(b.Bundle); err != nil {
		return nil, err
	}

	verifier, err := verify.NewSignedEntityVerifier(
		trustRoot,
		verify.WithSignedCertificateTimestamps(1),
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1),
	)
	if err != nil {
		return nil, fmt.Errorf("creating signed entity verifier: %w", err)
	}

	// Cert identity: pin OIDCIssuer exact + GithubWorkflowRepository extension
	// exact. The SAN regex is permissive (matches any non-empty value) because
	// the SPEC-canonical workflow-ref check runs post-verification against
	// the .1.6 extension below.
	sanMatcher, err := verify.NewSANMatcher("", ".+")
	if err != nil {
		return nil, fmt.Errorf("creating SAN matcher: %w", err)
	}
	issuerMatcher, err := verify.NewIssuerMatcher(policy.OIDCIssuer, "")
	if err != nil {
		return nil, fmt.Errorf("creating issuer matcher: %w", err)
	}
	exts := certificate.Extensions{}
	if policy.WorkflowRepository != "" {
		exts.GithubWorkflowRepository = policy.WorkflowRepository
	}
	certID, err := verify.NewCertificateIdentity(sanMatcher, issuerMatcher, exts)
	if err != nil {
		return nil, fmt.Errorf("creating certificate identity: %w", err)
	}

	digestBytes, err := hex.DecodeString(expectedDigest)
	if err != nil {
		return nil, fmt.Errorf("BUNDLE_MALFORMED: decoding expected digest hex: %w", err)
	}
	result, err := verifier.Verify(
		&b,
		verify.NewPolicy(
			verify.WithArtifactDigest("sha256", digestBytes),
			verify.WithCertificateIdentity(certID),
		),
	)
	if err != nil {
		return nil, classifyVerifyError(err)
	}

	// SPEC §5.2: reject duplicate-log SCTs (sigstore-go dedups rather than
	// rejecting). Mirrors the production VerifyBundle path and rs/js.
	if err := checkDuplicateSCTLogs(leafCertDERFromBundleJSON(bundleJSON)); err != nil {
		return nil, err
	}

	// Pull the cert summary from the verification result so we can do the
	// SPEC §5.3-anchored workflow-ref prefix check on the .1.6 extension
	// directly.
	if result.Signature == nil || result.Signature.Certificate == nil {
		return nil, fmt.Errorf("BUNDLE_MALFORMED: verification result missing cert summary")
	}
	certSummary := result.Signature.Certificate
	if !strings.HasPrefix(certSummary.Extensions.GithubWorkflowRef, policy.WorkflowRefPrefix) {
		return nil, fmt.Errorf(
			"WORKFLOW_REF_PREFIX_MISMATCH: cert GitHubWorkflowRef extension %q does not start with policy.WorkflowRefPrefix %q",
			certSummary.Extensions.GithubWorkflowRef, policy.WorkflowRefPrefix,
		)
	}

	// In-toto + predicate post-checks.
	if result.Statement == nil {
		return nil, fmt.Errorf("BUNDLE_MALFORMED: verification result missing in-toto statement")
	}
	stmtType := result.Statement.Type
	if policy.InTotoStatementTypesAllowed != nil && !contains(policy.InTotoStatementTypesAllowed, stmtType) {
		return nil, fmt.Errorf(
			"IN_TOTO_STATEMENT_TYPE_NOT_ALLOWED: in-toto statement _type %q not in policy.InTotoStatementTypesAllowed",
			stmtType,
		)
	}
	predicateType := result.Statement.PredicateType
	if policy.PredicateTypesAllowed != nil && !contains(policy.PredicateTypesAllowed, predicateType) {
		return nil, fmt.Errorf(
			"PREDICATE_TYPE_NOT_ALLOWED: predicate type %q not in policy.PredicateTypesAllowed",
			predicateType,
		)
	}

	// SPEC §5.4: only subject[0] is checked against the expected artifact
	// digest. sigstore-go's WithArtifactDigest matched the digest against ANY
	// subject in the statement (valid generic in-toto semantics), so we must
	// re-check subject[0] specifically to honor the SPEC and match the other
	// Tinfoil SDKs (rs/py/js).
	if err := enforceSubject0Digest(result, expectedDigest); err != nil {
		return nil, err
	}
	// Read subject[0] for diagnostic output (lowercase-normalize per SPEC §7.3).
	subj := result.Statement.Subject[0]
	subjDigest := subj.Digest["sha256"]

	// Extract registers for SnpTdxMultiPlatformV1; matches Rust/JS/Python.
	measurement, err := extractMeasurement(predicateType, result.Statement.GetPredicate())
	if err != nil {
		return nil, err
	}

	// Bundle observables (rekor log id, integrated time, tlog count, sct count).
	rekorLogIDHex, integratedTime, tlogCount := extractRekorObservables(bundleJSON)
	sctCount := extractSCTCountFromBundle(bundleJSON)

	v := &Verification{
		Measurement:             measurement,
		PredicateType:           predicateType,
		InTotoStatementType:     stmtType,
		SubjectName:             subj.Name,
		SubjectDigestSHA256Hex:  strings.ToLower(subjDigest),
		CertOIDCIssuer:          certSummary.Extensions.Issuer,
		CertWorkflowRepository:  certSummary.Extensions.GithubWorkflowRepository,
		CertWorkflowSignerURI:   certSummary.Extensions.BuildSignerURI,
		RekorLogIDHex:           rekorLogIDHex,
		RekorIntegratedTimeUnix: integratedTime,
		TLogEntryCount:          tlogCount,
		SCTCount:                sctCount,
	}
	return v, nil
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// extractMeasurement pulls the Tinfoil predicate registers out of the
// verified in-toto statement's predicate. Currently only
// SnpTdxMultiPlatformV1 is fully extracted (matches Rust/JS/Python).
func extractMeasurement(pt string, pred *structpb.Struct) (*MeasurementOutput, error) {
	if pt != "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1" {
		return nil, fmt.Errorf(
			"PREDICATE_MEASUREMENT_INVALID: predicate type %q allowed by policy but extraction not implemented in tinfoil-go",
			pt,
		)
	}
	if pred == nil {
		return nil, fmt.Errorf("PREDICATE_MEASUREMENT_INVALID: missing predicate")
	}
	fields := pred.GetFields()

	snpField, ok := fields["snp_measurement"]
	if !ok || snpField == nil {
		return nil, fmt.Errorf("PREDICATE_MEASUREMENT_INVALID: SnpTdxMultiPlatformV1 missing snp_measurement")
	}
	snp := snpField.GetStringValue()
	tdxField, ok := fields["tdx_measurement"]
	if !ok || tdxField == nil {
		return nil, fmt.Errorf("PREDICATE_MEASUREMENT_INVALID: SnpTdxMultiPlatformV1 missing tdx_measurement")
	}
	tdx := tdxField.GetStructValue()
	if tdx == nil {
		return nil, fmt.Errorf("PREDICATE_MEASUREMENT_INVALID: tdx_measurement is not a struct")
	}
	tdxFields := tdx.GetFields()

	rtmr1Field, ok := tdxFields["rtmr1"]
	if !ok || rtmr1Field == nil {
		return nil, fmt.Errorf("PREDICATE_MEASUREMENT_INVALID: SnpTdxMultiPlatformV1 missing tdx_measurement.rtmr1")
	}
	rtmr2Field, ok := tdxFields["rtmr2"]
	if !ok || rtmr2Field == nil {
		return nil, fmt.Errorf("PREDICATE_MEASUREMENT_INVALID: SnpTdxMultiPlatformV1 missing tdx_measurement.rtmr2")
	}
	return &MeasurementOutput{
		Type: pt,
		Registers: []string{
			snp,
			rtmr1Field.GetStringValue(),
			rtmr2Field.GetStringValue(),
		},
	}, nil
}

// extractRekorObservables parses the bundle JSON and returns the first tlog
// entry's logId (hex), integratedTime, and the count of tlog entries.
// Pure observation; no verification.
func extractRekorObservables(bundleJSON []byte) (string, int64, int) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(bundleJSON, &raw); err != nil {
		return "", 0, 0
	}
	vmRaw, ok := raw["verificationMaterial"]
	if !ok {
		return "", 0, 0
	}
	var vm map[string]json.RawMessage
	if err := json.Unmarshal(vmRaw, &vm); err != nil {
		return "", 0, 0
	}
	entriesRaw, ok := vm["tlogEntries"]
	if !ok {
		return "", 0, 0
	}
	var entries []map[string]json.RawMessage
	if err := json.Unmarshal(entriesRaw, &entries); err != nil {
		return "", 0, 0
	}
	if len(entries) == 0 {
		return "", 0, len(entries)
	}
	first := entries[0]
	var logID struct {
		KeyID string `json:"keyId"`
	}
	if li, ok := first["logId"]; ok {
		_ = json.Unmarshal(li, &logID)
	}
	logIDHex := ""
	if logID.KeyID != "" {
		if b, err := base64.StdEncoding.DecodeString(logID.KeyID); err == nil {
			logIDHex = hex.EncodeToString(b)
		}
	}
	var integrated int64
	if it, ok := first["integratedTime"]; ok {
		// integratedTime is a JSON string of an integer in v0.3 bundles
		var s string
		if err := json.Unmarshal(it, &s); err == nil {
			fmt.Sscanf(s, "%d", &integrated)
		} else {
			_ = json.Unmarshal(it, &integrated)
		}
	}
	return logIDHex, integrated, len(entries)
}

// extractSCTCountFromBundle parses the leaf cert from the bundle JSON and
// counts the SCTs in its SCT extension. Mirrors what the Rust/JS/Python
// conformance binaries emit so the harness sees the same value.
func extractSCTCountFromBundle(bundleJSON []byte) int {
	der := leafCertDERFromBundleJSON(bundleJSON)
	if der == nil {
		return -1
	}
	count, err := CountSCTsInCertDER(der)
	if err != nil {
		return -1
	}
	return count
}

// leafCertDERFromBundleJSON pulls the leaf certificate's raw DER out of a
// bundle's JSON, handling the single-certificate layout. Returns nil if absent
// or malformed.
func leafCertDERFromBundleJSON(bundleJSON []byte) []byte {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(bundleJSON, &raw); err != nil {
		return nil
	}
	vmRaw, ok := raw["verificationMaterial"]
	if !ok {
		return nil
	}
	var vm map[string]json.RawMessage
	if err := json.Unmarshal(vmRaw, &vm); err != nil {
		return nil
	}
	certWrap, ok := vm["certificate"]
	if !ok {
		return nil
	}
	var certObj struct {
		RawBytes string `json:"rawBytes"`
	}
	if err := json.Unmarshal(certWrap, &certObj); err != nil {
		return nil
	}
	if certObj.RawBytes == "" {
		return nil
	}
	der, err := base64.StdEncoding.DecodeString(certObj.RawBytes)
	if err != nil {
		return nil
	}
	return der
}

// CountSCTsInCertDER hand-parses the SCT extension (OID
// 1.3.6.1.4.1.11129.2.4.2) and counts entries. Mirrors the equivalents in
// the Rust/JS/Python conformance binaries so the harness sees the same value.
func CountSCTsInCertDER(certDER []byte) (int, error) {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return 0, err
	}
	sctOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(sctOID) {
			continue
		}
		// ext.Value is the contents of the outer DER OCTET STRING that
		// x509 parsing has already unwrapped. The inner content is *another*
		// OCTET STRING (per RFC 6962 §3.3) wrapping the SerializedSCTList.
		var inner []byte
		if _, err := asn1.Unmarshal(ext.Value, &inner); err != nil {
			return 0, err
		}
		if len(inner) < 2 {
			return 0, fmt.Errorf("SCT extension body too short")
		}
		totalLen := int(inner[0])<<8 | int(inner[1])
		body := inner[2:]
		if totalLen <= len(body) {
			body = body[:totalLen]
		}
		count := 0
		i := 0
		for i+2 <= len(body) {
			sctLen := int(body[i])<<8 | int(body[i+1])
			i += 2
			if i+sctLen > len(body) {
				return 0, fmt.Errorf("SCT extension parse: entry beyond body")
			}
			i += sctLen
			count++
		}
		return count, nil
	}
	return 0, nil
}

// sha256Hex is a tiny convenience.
func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// classifyVerifyError leaves sigstore-go's error string mostly intact but
// adds a stable rejection-code prefix so the conformance binary's classifier
// can map it. Most callers map on substring; we still tag the common cases
// for clarity.
func classifyVerifyError(err error) error {
	msg := err.Error()
	low := strings.ToLower(msg)
	switch {
	case strings.Contains(low, "no matching certificateidentity"):
		return fmt.Errorf("%w", err)
	case strings.Contains(low, "artifact digest"):
		return fmt.Errorf("SUBJECT_DIGEST_MISMATCH: %w", err)
	}
	return err
}
