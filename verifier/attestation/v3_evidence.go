package attestation

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/textproto"
	"net/url"
	"strings"

	"github.com/google/go-sev-guest/kds"
	"github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-sev-guest/validate"
	tdxabi "github.com/google/go-tdx-guest/abi"
	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
	tdxverify "github.com/google/go-tdx-guest/verify"
	tdxtrust "github.com/google/go-tdx-guest/verify/trust"

	"github.com/tinfoilsh/tinfoil-go/verifier/policy"
)

// EvidenceV3 is the result of verifying a v3 document's CPU evidence: the
// authenticated platform facts a caller may rely on after verification.
type EvidenceV3 struct {
	// Platform is policy.PlatformSEVSNP or policy.PlatformTDX.
	Platform string
	// PlatformIdentity is the endorsed machine identifier extracted from
	// authenticated evidence (SEV CHIP_ID / TDX PPID), lowercase hex.
	PlatformIdentity string
	// PolicyName is the appraisal policy the machine is endorsed with.
	PolicyName string
	// Measurement carries the launch measurement (SEV) or MRTD+RTMRs (TDX).
	Measurement *Measurement
}

// AuthenticatedQuote holds the quote fields authenticated by VerifyQuoteV3.
// Nothing in it has been compared against expected values yet: that is
// ValidateQuoteV3's job.
type AuthenticatedQuote struct {
	// Platform is policy.PlatformSEVSNP or policy.PlatformTDX.
	Platform string
	// PlatformIdentity is the machine identifier from authenticated bytes
	// (SEV CHIP_ID / TDX PPID from the PCK leaf), lowercase hex.
	PlatformIdentity string
	// Measurement is the launch measurement (SEV) or MRTD+RTMRs (TDX).
	Measurement *Measurement

	reportData []byte
	sev        *sevsnp.Attestation
	tdx        *tdxpb.QuoteV4
	// tdxTCBEvaluationDataNumber is the minimum tcbEvaluationDataNumber
	// observed in the verified Intel collateral.
	tdxTCBEvaluationDataNumber int
}

// AssembledPolicy is the complete expected state of a quote, resolved from
// verified reference values before validation runs.
type AssembledPolicy struct {
	// PolicyName is the matched appraisal policy name.
	PolicyName string
	// ReportData is the expected REPORT_DATA from the envelope.
	ReportData [64]byte
	// CodeMeasurement is the expected launch measurement from verified code
	// provenance. When nil, the launch-measurement comparison is skipped and
	// the caller is responsible for it.
	CodeMeasurement *Measurement

	artifact *policy.Artifact
	machine  *policy.Policy
}

// VerifyQuoteV3 verifies the authenticity of a v3 document's CPU quote: the
// signature chain up to the pinned vendor roots, using the endorsement
// collateral (VCEK / Intel PCS captures) carried in the document itself —
// verification is single-request and performs no network fetches. It makes
// no reference-value comparison; callers must assemble a policy and run
// ValidateQuoteV3 before trusting the platform.
func VerifyQuoteV3(doc *DocumentV3) (*AuthenticatedQuote, error) {
	switch doc.CPUEvidence.Format {
	case SEVSNPReportV1Format:
		return verifySevQuoteV3(doc)
	case TDXQuoteV1Format:
		return verifyTdxQuoteV3(doc)
	default:
		return nil, fmt.Errorf("unsupported cpu_evidence format %q", doc.CPUEvidence.Format)
	}
}

// AssemblePolicyV3 resolves the complete expected state of an authenticated
// quote: the machines-map lookup keyed by the authenticated platform
// identity (a machine absent from the map is not endorsed), the expected
// REPORT_DATA, and the expected launch measurement. codeMeasurement may be
// nil when the caller compares the launch measurement itself.
func AssemblePolicyV3(endorsements *policy.Artifact, codeMeasurement *Measurement, expectedReportData [64]byte, quote *AuthenticatedQuote) (*AssembledPolicy, error) {
	name, machinePolicy, err := endorsements.PolicyFor(quote.PlatformIdentity, quote.Platform)
	if err != nil {
		return nil, err
	}
	return &AssembledPolicy{
		PolicyName:      name,
		ReportData:      expectedReportData,
		CodeMeasurement: codeMeasurement,
		artifact:        endorsements,
		machine:         machinePolicy,
	}, nil
}

// ValidateQuoteV3 compares an authenticated quote against an assembled
// policy: REPORT_DATA equality, the platform policy block, and (when
// present) the expected launch measurement. It performs no lookups and no
// recomputation.
func ValidateQuoteV3(quote *AuthenticatedQuote, assembled *AssembledPolicy) error {
	if !bytes.Equal(quote.reportData, assembled.ReportData[:]) {
		return fmt.Errorf("quote REPORT_DATA does not match the recomputed value")
	}

	switch quote.Platform {
	case policy.PlatformSEVSNP:
		productLine := kds.ProductLine(quote.sev.GetProduct())
		valOpts, err := assembled.machine.SEVSNP.SEVOptions(productLine)
		if err != nil {
			return err
		}
		if err := validate.SnpAttestation(quote.sev, valOpts); err != nil {
			return err
		}
	case policy.PlatformTDX:
		if err := assembled.artifact.ValidateTDXQuote(assembled.machine.TDX, quote.tdx, quote.tdxTCBEvaluationDataNumber); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported platform %q", quote.Platform)
	}

	if assembled.CodeMeasurement != nil {
		if err := assembled.CodeMeasurement.Equals(quote.Measurement); err != nil {
			return err
		}
	}
	return nil
}

// VerifyCPUEvidenceV3 composes VerifyQuoteV3, AssemblePolicyV3, and
// ValidateQuoteV3 without a launch-measurement expectation; callers must
// compare the returned Measurement against verified code provenance.
func VerifyCPUEvidenceV3(doc *DocumentV3, expectedReportData [64]byte, endorsements *policy.Artifact) (*EvidenceV3, error) {
	quote, err := VerifyQuoteV3(doc)
	if err != nil {
		return nil, err
	}
	assembled, err := AssemblePolicyV3(endorsements, nil, expectedReportData, quote)
	if err != nil {
		return nil, err
	}
	if err := ValidateQuoteV3(quote, assembled); err != nil {
		return nil, err
	}
	return &EvidenceV3{
		Platform:         quote.Platform,
		PlatformIdentity: quote.PlatformIdentity,
		PolicyName:       assembled.PolicyName,
		Measurement:      quote.Measurement,
	}, nil
}

// endorsementCollateral returns the first endorsement-role collateral entry
// with the given format whose subjects include subject.
func (d *DocumentV3) endorsementCollateral(format, subject string) (*CollateralEntry, bool) {
	for i := range d.Collateral {
		entry := &d.Collateral[i]
		if entry.Role != RoleEndorsement || entry.Format != format {
			continue
		}
		for _, s := range entry.Subjects {
			if s == subject {
				return entry, true
			}
		}
	}
	return nil, false
}

// ReferenceValuesCollateral returns the first reference-values collateral
// entry with the given format, parsed as a Sigstore collateral payload.
func (d *DocumentV3) ReferenceValuesCollateral(format string) (*SigstoreCollateral, bool, error) {
	for i := range d.Collateral {
		entry := &d.Collateral[i]
		if entry.Role != RoleReferenceValues || entry.Format != format {
			continue
		}
		var sc SigstoreCollateral
		if err := strictUnmarshal(entry.Data, &sc); err != nil {
			return nil, true, fmt.Errorf("parsing %s collateral entry %q: %w", format, entry.ID, err)
		}
		return &sc, true, nil
	}
	return nil, false, nil
}

func verifySevQuoteV3(doc *DocumentV3) (*AuthenticatedQuote, error) {
	// The VCEK comes from the document's own collateral; its chain is
	// verified against the pinned AMD root, so the entry is untrusted input.
	entry, ok := doc.endorsementCollateral(CollateralAMDVCEKV1Format, SubjectCPU)
	if !ok {
		return nil, fmt.Errorf("document carries no amd-vcek endorsement collateral for the cpu")
	}
	var data AMDVCEKCollateral
	if err := strictUnmarshal(entry.Data, &data); err != nil {
		return nil, fmt.Errorf("parsing amd-vcek collateral entry %q: %w", entry.ID, err)
	}
	vcekDER, err := base64.StdEncoding.DecodeString(data.VCEKDERBase64)
	if err != nil {
		return nil, fmt.Errorf("decoding vcek_der_base64: %w", err)
	}

	attestation, err := verifySevSignature(doc.CPUEvidence.ReportBase64, false, vcekDER)
	if err != nil {
		return nil, err
	}
	report := attestation.GetReport()

	identity, err := policy.SEVIdentity(report.GetChipId())
	if err != nil {
		return nil, err
	}

	return &AuthenticatedQuote{
		Platform:         policy.PlatformSEVSNP,
		PlatformIdentity: identity,
		Measurement: &Measurement{
			Type:      SevGuestV2,
			Registers: []string{hex.EncodeToString(report.Measurement)},
		},
		reportData: report.ReportData,
		sev:        attestation,
	}, nil
}

func verifyTdxQuoteV3(doc *DocumentV3) (*AuthenticatedQuote, error) {
	rawQuote, err := base64.StdEncoding.DecodeString(doc.CPUEvidence.ReportBase64)
	if err != nil {
		return nil, fmt.Errorf("decoding TDX quote: %w", err)
	}
	parsed, err := tdxabi.QuoteToProto(rawQuote)
	if err != nil {
		return nil, fmt.Errorf("parsing TDX quote: %w", err)
	}
	quote, ok := parsed.(*tdxpb.QuoteV4)
	if !ok {
		return nil, fmt.Errorf("unsupported TDX quote version (want v4)")
	}

	// Intel PCS collateral is replayed from the document's own captures —
	// no network fetch. The recorder observes the tcbEvaluationDataNumber of
	// the TCB Info and QE Identity actually used so the policy floor is
	// enforced on verified collateral.
	entry, ok := doc.endorsementCollateral(CollateralIntelPCSV1Format, SubjectCPU)
	if !ok {
		return nil, fmt.Errorf("document carries no intel-pcs endorsement collateral for the cpu")
	}
	var data IntelPCSCollateral
	if err := strictUnmarshal(entry.Data, &data); err != nil {
		return nil, fmt.Errorf("parsing intel-pcs collateral entry %q: %w", entry.ID, err)
	}
	inner, err := newPCSReplayGetter(data.Responses)
	if err != nil {
		return nil, err
	}
	recorder := &tcbEvaluationRecorder{inner: inner}

	opts := tdxverify.DefaultOptions()
	opts.Getter = recorder
	opts.TrustedRoots = intelRootCertPool
	opts.GetCollateral = true
	opts.CheckRevocations = true
	if err := tdxverify.TdxQuote(parsed, opts); err != nil {
		return nil, fmt.Errorf("verifying TDX quote: %w", err)
	}

	identity, err := policy.TDXIdentity(quote)
	if err != nil {
		return nil, err
	}
	tcbEvaluationDataNumber, err := recorder.minimum()
	if err != nil {
		return nil, err
	}

	body := quote.GetTdQuoteBody()
	registers := []string{hex.EncodeToString(body.GetMrTd())}
	for _, rtmr := range body.GetRtmrs() {
		registers = append(registers, hex.EncodeToString(rtmr))
	}
	return &AuthenticatedQuote{
		Platform:         policy.PlatformTDX,
		PlatformIdentity: identity,
		Measurement: &Measurement{
			Type:      TdxGuestV2,
			Registers: registers,
		},
		reportData:                 body.GetReportData(),
		tdx:                        quote,
		tdxTCBEvaluationDataNumber: tcbEvaluationDataNumber,
	}, nil
}

// pcsCollateralKey canonicalizes an Intel PCS URL for replay lookup: the
// tcbEvaluationDataNumber query parameter selects which collateral edition
// Intel serves, so a capture made at a specific number must still answer the
// library's parameterless request for the same resource.
func pcsCollateralKey(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("parsing PCS URL %q: %w", rawURL, err)
	}
	q := u.Query()
	q.Del("tcbEvaluationDataNumber")
	u.RawQuery = q.Encode()
	return u.String(), nil
}

type pcsReplayGetter struct {
	responses map[string]*PCSResponse
}

func newPCSReplayGetter(responses []PCSResponse) (*pcsReplayGetter, error) {
	m := make(map[string]*PCSResponse, len(responses))
	for i := range responses {
		key, err := pcsCollateralKey(responses[i].URL)
		if err != nil {
			return nil, err
		}
		m[key] = &responses[i]
	}
	return &pcsReplayGetter{responses: m}, nil
}

func (g *pcsReplayGetter) Get(requestURL string) (map[string][]string, []byte, error) {
	key, err := pcsCollateralKey(requestURL)
	if err != nil {
		return nil, nil, err
	}
	resp, ok := g.responses[key]
	if !ok {
		return nil, nil, fmt.Errorf("intel-pcs collateral has no captured response for %s", requestURL)
	}
	body, err := base64.StdEncoding.DecodeString(resp.BodyBase64)
	if err != nil {
		return nil, nil, fmt.Errorf("decoding captured PCS response body for %s: %w", requestURL, err)
	}
	// Header keys are matched verbatim by go-tdx-guest (canonical MIME form),
	// so normalize whatever casing the capture used.
	headers := make(map[string][]string, len(resp.Headers))
	for k, v := range resp.Headers {
		headers[textproto.CanonicalMIMEHeaderKey(k)] = v
	}
	return headers, body, nil
}

// tcbEvaluationRecorder observes the tcbEvaluationDataNumber carried by the
// TCB Info and QE Identity responses that quote verification consumes.
type tcbEvaluationRecorder struct {
	inner      tdxtrust.HTTPSGetter
	tcbInfo    *int
	qeIdentity *int
}

func (r *tcbEvaluationRecorder) Get(requestURL string) (map[string][]string, []byte, error) {
	headers, body, err := r.inner.Get(requestURL)
	if err != nil {
		return nil, nil, err
	}

	u, parseErr := url.Parse(requestURL)
	if parseErr != nil {
		return headers, body, nil
	}
	switch {
	case strings.HasSuffix(u.Path, "/tcb"):
		var resp struct {
			TcbInfo struct {
				TcbEvaluationDataNumber int `json:"tcbEvaluationDataNumber"`
			} `json:"tcbInfo"`
		}
		if json.Unmarshal(body, &resp) == nil {
			n := resp.TcbInfo.TcbEvaluationDataNumber
			r.tcbInfo = &n
		}
	case strings.HasSuffix(u.Path, "/qe/identity"):
		var resp struct {
			EnclaveIdentity struct {
				TcbEvaluationDataNumber int `json:"tcbEvaluationDataNumber"`
			} `json:"enclaveIdentity"`
		}
		if json.Unmarshal(body, &resp) == nil {
			n := resp.EnclaveIdentity.TcbEvaluationDataNumber
			r.qeIdentity = &n
		}
	}
	return headers, body, nil
}

// minimum returns the lower of the two observed numbers; both responses must
// have been seen (quote verification always fetches both when it succeeds).
func (r *tcbEvaluationRecorder) minimum() (int, error) {
	if r.tcbInfo == nil || r.qeIdentity == nil {
		return 0, fmt.Errorf("collateral tcbEvaluationDataNumber was not observed during quote verification")
	}
	if *r.qeIdentity < *r.tcbInfo {
		return *r.qeIdentity, nil
	}
	return *r.tcbInfo, nil
}
