// Package tdx authenticates Intel TDX quotes against the pinned Intel SGX
// root, replaying the document's own captured PCS collateral, and assembles
// complete go-tdx-guest validation options from an endorsed policy.
package tdx

import (
	"bytes"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/textproto"
	"net/url"
	"strings"
	"time"

	tdxabi "github.com/google/go-tdx-guest/abi"
	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
	tdxverify "github.com/google/go-tdx-guest/verify"
	tdxtrust "github.com/google/go-tdx-guest/verify/trust"

	"github.com/tinfoilsh/tinfoil-go/verifier/envelope"
	"github.com/tinfoilsh/tinfoil-go/verifier/internal/strictjson"
	"github.com/tinfoilsh/tinfoil-go/verifier/measurement"
)

// Quote is a signature-verified TDX quote, not yet compared against any
// expected value.
type Quote struct {
	// Identity is the machines-map lookup key (PPID, lowercase hex).
	Identity string
	// Measurement carries MRTD followed by the four RTMRs.
	Measurement *measurement.Measurement
	// TCBEvaluationDataNumber is the minimum tcbEvaluationDataNumber
	// observed in the verified Intel collateral.
	TCBEvaluationDataNumber int

	quote *tdxpb.QuoteV4
}

// Authenticate verifies the quote's signature chain up to the pinned Intel
// SGX root, replaying the document's captured PCS collateral — no network
// fetches. Callers must assemble a policy and validate before trusting the
// platform.
func Authenticate(doc *envelope.Document) (*Quote, error) {
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
	// The library parses but never constrains these: header bytes 8-11 are
	// reserved in quote v4 (exposed as QeSvn/PceSvn), and bytes past the
	// signed data are kept as ExtraBytes. Reserved bytes must be zero;
	// trailing bytes may only be the zero padding of the fixed-size buffer
	// the quote was read from — anything non-zero is unsigned content.
	header := quote.GetHeader()
	if !bytes.Equal(header.GetQeSvn(), []byte{0, 0}) || !bytes.Equal(header.GetPceSvn(), []byte{0, 0}) {
		return nil, fmt.Errorf("TDX quote header carries non-zero reserved bytes")
	}
	for _, b := range quote.GetExtraBytes() {
		if b != 0 {
			return nil, fmt.Errorf("TDX quote carries non-zero bytes after the signed data")
		}
	}

	// The recorder observes the tcbEvaluationDataNumber of the collateral
	// actually used, so the policy floor is enforced on verified bytes.
	entry, ok := doc.EndorsementCollateral(envelope.CollateralIntelPCSV1Format, envelope.SubjectCPU)
	if !ok {
		return nil, fmt.Errorf("document carries no intel-pcs endorsement collateral for the cpu")
	}
	var data envelope.IntelPCSCollateral
	if err := strictjson.Unmarshal(entry.Data, &data); err != nil {
		return nil, fmt.Errorf("parsing intel-pcs collateral entry %q: %w", entry.ID, err)
	}
	inner, err := newPCSReplayGetter(data.Responses)
	if err != nil {
		return nil, err
	}
	recorder := &tcbEvaluationRecorder{inner: inner}

	// All options explicit: collateral replayed from the document, chain
	// pinned to the embedded Intel root, revocation checking on, validity
	// evaluated at the current time.
	opts := &tdxverify.Options{
		Getter:           recorder,
		TrustedRoots:     intelRootCertPool,
		GetCollateral:    true,
		CheckRevocations: true,
		Now:              timeNow(),
	}
	if err := tdxverify.TdxQuote(parsed, opts); err != nil {
		return nil, fmt.Errorf("verifying TDX quote: %w", err)
	}

	identity, err := Identity(quote)
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
	return &Quote{
		Identity: identity,
		Measurement: &measurement.Measurement{
			Type:      measurement.TdxGuestV2,
			Registers: registers,
		},
		TCBEvaluationDataNumber: tcbEvaluationDataNumber,
		quote:                   quote,
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
	responses map[string]*envelope.PCSResponse
}

func newPCSReplayGetter(responses []envelope.PCSResponse) (*pcsReplayGetter, error) {
	m := make(map[string]*envelope.PCSResponse, len(responses))
	for i := range responses {
		key, err := pcsCollateralKey(responses[i].URL)
		if err != nil {
			return nil, err
		}
		m[strings.ToLower(key)] = &responses[i]
	}
	return &pcsReplayGetter{responses: m}, nil
}

func (g *pcsReplayGetter) Get(requestURL string) (map[string][]string, []byte, error) {
	key, err := pcsCollateralKey(requestURL)
	if err != nil {
		return nil, nil, err
	}
	key = strings.ToLower(key)
	resp, ok := g.responses[key]
	if !ok {
		return nil, nil, fmt.Errorf("intel-pcs collateral has no captured response for %s", requestURL)
	}
	body, err := base64.StdEncoding.DecodeString(resp.BodyBase64)
	if err != nil {
		return nil, nil, fmt.Errorf("decoding captured PCS response body for %s: %w", requestURL, err)
	}
	// The library checks CRL NextUpdate but not ThisUpdate, so a
	// future-dated capture would otherwise pass. Intel also serves a root-CA
	// CRL from a .der URL that does not identify the body as a CRL.
	crl, crlErr := x509.ParseRevocationList(body)
	if crlErr == nil {
		if now := timeNow(); now.Before(crl.ThisUpdate) || now.After(crl.NextUpdate) {
			return nil, nil, fmt.Errorf("captured CRL for %s is outside its validity window", requestURL)
		}
	} else if strings.Contains(key, "crl") {
		return nil, nil, fmt.Errorf("parsing captured CRL for %s: %w", requestURL, crlErr)
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

	// Parse failures below are ignored on purpose: these bytes are
	// authenticated and interpreted by the verification library, and this
	// wrapper only observes one field. A response that never parses leaves
	// its pointer nil, which fails minimum() after verification.
	u, parseErr := url.Parse(requestURL)
	if parseErr != nil {
		return headers, body, nil
	}
	switch {
	case strings.HasSuffix(u.Path, "/tcb"):
		var resp struct {
			TcbInfo struct {
				TcbEvaluationDataNumber *int `json:"tcbEvaluationDataNumber"`
			} `json:"tcbInfo"`
		}
		if json.Unmarshal(body, &resp) == nil && resp.TcbInfo.TcbEvaluationDataNumber != nil {
			r.tcbInfo = resp.TcbInfo.TcbEvaluationDataNumber
		}
	case strings.HasSuffix(u.Path, "/qe/identity"):
		var resp struct {
			EnclaveIdentity struct {
				TcbEvaluationDataNumber *int `json:"tcbEvaluationDataNumber"`
			} `json:"enclaveIdentity"`
		}
		if json.Unmarshal(body, &resp) == nil && resp.EnclaveIdentity.TcbEvaluationDataNumber != nil {
			r.qeIdentity = resp.EnclaveIdentity.TcbEvaluationDataNumber
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

//go:generate sh -xc "curl -fo sgx_root_ca.pem https://certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.pem"

//go:embed sgx_root_ca.pem
var sgxRootCACertPEM []byte

var intelRootCertPool *x509.CertPool

// timeNow is the validity-window clock; the production default, overridden only
// by the conformance build to replay a frozen document at its capture time.
var timeNow = time.Now

func init() {
	root, _ := pem.Decode(sgxRootCACertPEM)
	if root == nil {
		panic("embedded Intel root certificate is not valid PEM")
	}
	cert, err := x509.ParseCertificate(root.Bytes)
	if err != nil {
		panic("failed to parse Intel root certificate: " + err.Error())
	}
	intelRootCertPool = x509.NewCertPool()
	intelRootCertPool.AddCert(cert)
}
