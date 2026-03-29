package attestation

import (
	"bytes"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/url"
	"strings"
	"sync"

	"github.com/google/go-tdx-guest/abi"
	pb "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/go-tdx-guest/validate"
	"github.com/google/go-tdx-guest/verify"

	"github.com/tinfoilsh/tinfoil-go/verifier/util"
)

//go:generate sh -xc "curl -o sgx_root_ca.pem https://certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.pem"

//go:embed sgx_root_ca.pem
var sgxRootCACertPEM []byte

// MinimumTcbEvaluationDataNumber is the minimum TCB evaluation data number
// required for collateral. This prevents accepting collateral issued before
// critical security updates. See Intel's TCB Recovery best practices.
const MinimumTcbEvaluationDataNumber = 18

// IntelQeVendorID is Intel's QE Vendor ID (939a7233-f79c-4ca9-940a-0db3957f0607)
var IntelQeVendorID = []byte{
	0x93, 0x9a, 0x72, 0x33, 0xf7, 0x9c, 0x4c, 0xa9,
	0x94, 0x0a, 0x0d, 0xb3, 0x95, 0x7f, 0x06, 0x07,
}

var intelRootCertPool *x509.CertPool

func init() {
	root, _ := pem.Decode(sgxRootCACertPEM)
	cert, err := x509.ParseCertificate(root.Bytes)
	if err != nil {
		panic("failed to parse Intel root certificate: " + err.Error())
	}
	intelRootCertPool = x509.NewCertPool()
	intelRootCertPool.AddCert(cert)
}

// TDXGetterOption configures a TDXGetter.
type TDXGetterOption func(*tdxGetter)

// WithProxyServer routes collateral requests through a proxy, encoding the
// original host as a path prefix (e.g. https://proxy.example.com/api.intel.com/path).
func WithProxyServer(host string) TDXGetterOption {
	return func(g *tdxGetter) {
		g.proxyHost = host
	}
}

// NewTDXGetter creates a TDX collateral getter that implements the
// verify/trust.HTTPSGetter interface with in-memory caching.
func NewTDXGetter(opts ...TDXGetterOption) *tdxGetter {
	g := &tdxGetter{}
	for _, opt := range opts {
		opt(g)
	}
	return g
}

type tdxGetter struct {
	proxyHost string
}

type collateralCacheEntry struct {
	headers map[string][]string
	body    []byte
}

var (
	collateralCache   = make(map[string]*collateralCacheEntry)
	collateralCacheMu sync.RWMutex
)

// Get implements verify/trust.HTTPSGetter
func (t *tdxGetter) Get(requestURL string) (map[string][]string, []byte, error) {
	collateralCacheMu.RLock()
	if entry, ok := collateralCache[requestURL]; ok {
		collateralCacheMu.RUnlock()
		return entry.headers, entry.body, nil
	}
	collateralCacheMu.RUnlock()

	// Inject the Intel TDX API proxy if set
	fetchURL := requestURL
	if t.proxyHost != "" {
		parsed, err := url.Parse(requestURL)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse collateral URL: %w", err)
		}
		fetchURL = fmt.Sprintf("https://%s/%s%s", t.proxyHost, parsed.Host, parsed.RequestURI())
	}

	body, headers, err := util.Get(fetchURL)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch collateral from %s: %w", requestURL, err)
	}

	if err := validateTcbEvaluationDataNumber(requestURL, body); err != nil {
		return nil, nil, err
	}

	collateralCacheMu.Lock()
	collateralCache[requestURL] = &collateralCacheEntry{headers: headers, body: body}
	collateralCacheMu.Unlock()

	return headers, body, nil
}

// validateTcbEvaluationDataNumber checks that fetched QE Identity and TCB Info
// collateral meets the minimum tcbEvaluationDataNumber threshold, rejecting
// collateral issued before critical security updates.
func validateTcbEvaluationDataNumber(requestURL string, body []byte) error {
	if strings.Contains(requestURL, "/qe/identity") {
		var resp struct {
			EnclaveIdentity struct {
				TcbEvaluationDataNumber int `json:"tcbEvaluationDataNumber"`
			} `json:"enclaveIdentity"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("failed to parse QE Identity response: %w", err)
		}
		if resp.EnclaveIdentity.TcbEvaluationDataNumber < MinimumTcbEvaluationDataNumber {
			return fmt.Errorf("QE Identity tcbEvaluationDataNumber %d is below minimum %d",
				resp.EnclaveIdentity.TcbEvaluationDataNumber, MinimumTcbEvaluationDataNumber)
		}
	}

	if strings.Contains(requestURL, "/tcb?fmspc=") {
		var resp struct {
			TcbInfo struct {
				TcbEvaluationDataNumber int `json:"tcbEvaluationDataNumber"`
			} `json:"tcbInfo"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("failed to parse TCB Info response: %w", err)
		}
		if resp.TcbInfo.TcbEvaluationDataNumber < MinimumTcbEvaluationDataNumber {
			return fmt.Errorf("TCB Info tcbEvaluationDataNumber %d is below minimum %d",
				resp.TcbInfo.TcbEvaluationDataNumber, MinimumTcbEvaluationDataNumber)
		}
	}

	return nil
}

func verifyTdxReport(attestationDoc string, isCompressed bool) ([]string, []byte, error) {
	attDocBytes, err := base64.StdEncoding.DecodeString(attestationDoc)
	if err != nil {
		return nil, nil, err
	}

	if isCompressed {
		attDocBytes, err = gzipDecompress(attDocBytes)
		if err != nil {
			return nil, nil, err
		}
	}

	opts := verify.DefaultOptions()
	opts.Getter = NewTDXGetter(WithProxyServer("tdx-proxy.tinfoil.sh"))
	opts.TrustedRoots = intelRootCertPool
	opts.GetCollateral = true
	opts.CheckRevocations = true

	parsedReport, err := abi.QuoteToProto(attDocBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse report: %w", err)
	}
	report, ok := parsedReport.(*pb.QuoteV4)
	if !ok {
		return nil, nil, fmt.Errorf("failed to convert to QuoteV4")
	}

	if err := verify.TdxQuote(parsedReport, opts); err != nil {
		return nil, nil, err
	}

	if len(report.TdQuoteBody.Rtmrs) != 4 {
		return nil, nil, fmt.Errorf("expected 4 RTMRs, got %d", len(report.TdQuoteBody.Rtmrs))
	}

	registers := []string{
		hex.EncodeToString(report.TdQuoteBody.MrTd),
		hex.EncodeToString(report.TdQuoteBody.Rtmrs[0]),
		hex.EncodeToString(report.TdQuoteBody.Rtmrs[1]),
		hex.EncodeToString(report.TdQuoteBody.Rtmrs[2]),
		hex.EncodeToString(report.TdQuoteBody.Rtmrs[3]),
	}

	// Validate Policy

	// MinimumTeeTcbSvn: 3.1.2
	expectedMinimumTeeTcbSvn := []byte{0x03, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	// MrSeam are provided by Intel https://github.com/intel/confidential-computing.tdx.tdx-module/releases
	AcceptedMrSeams := [][]byte{
		{0x47, 0x6a, 0x29, 0x97, 0xc6, 0x2b, 0xcc, 0xc7, 0x83, 0x70, 0x91, 0x3d, 0x0a, 0x80, 0xb9, 0x56, 0xe3, 0x72, 0x1b, 0x24, 0x27, 0x2b, 0xc6, 0x6c, 0x4d, 0x63, 0x07, 0xce, 0xd4, 0xbe, 0x28, 0x65, 0xc4, 0x0e, 0x26, 0xaf, 0xac, 0x75, 0xf1, 0x2d, 0xf3, 0x42, 0x5b, 0x03, 0xeb, 0x59, 0xea, 0x7c}, // 2.0.08
		{0x7b, 0xf0, 0x63, 0x28, 0x0e, 0x94, 0xfb, 0x05, 0x1f, 0x5d, 0xd7, 0xb1, 0xfc, 0x59, 0xce, 0x9a, 0xac, 0x42, 0xbb, 0x96, 0x1d, 0xf8, 0xd4, 0x4b, 0x70, 0x9c, 0x9b, 0x0f, 0xf8, 0x7a, 0x7b, 0x4d, 0xf6, 0x48, 0x65, 0x7b, 0xa6, 0xd1, 0x18, 0x95, 0x89, 0xfe, 0xab, 0x1d, 0x5a, 0x3c, 0x9a, 0x9d}, // 1.5.16
		{0x68, 0x5f, 0x89, 0x1e, 0xa5, 0xc2, 0x0e, 0x8f, 0xa2, 0x7b, 0x15, 0x1b, 0xf3, 0x4b, 0xf3, 0xb5, 0x0f, 0xba, 0xf7, 0x14, 0x3c, 0xc5, 0x36, 0x62, 0x72, 0x7c, 0xbd, 0xb1, 0x67, 0xc0, 0xad, 0x83, 0x85, 0xf1, 0xf6, 0xf3, 0x57, 0x15, 0x39, 0xa9, 0x1e, 0x10, 0x4a, 0x1c, 0x96, 0xd7, 0x5e, 0x04}, // 2.0.02
		{0x49, 0xb6, 0x6f, 0xaa, 0x45, 0x1d, 0x19, 0xeb, 0xbd, 0xbe, 0x89, 0x37, 0x1b, 0x8d, 0xaf, 0x2b, 0x65, 0xaa, 0x39, 0x84, 0xec, 0x90, 0x11, 0x03, 0x43, 0xe9, 0xe2, 0xee, 0xc1, 0x16, 0xaf, 0x08, 0x85, 0x0f, 0xa2, 0x0e, 0x3b, 0x1a, 0xa9, 0xa8, 0x74, 0xd7, 0x7a, 0x65, 0x38, 0x0e, 0xe7, 0xe6}, // 1.5.08
	}

	// TdAttributes: All zeros except SEPT_VE_DISABLE => 1
	expectedTdAttributes := []byte{0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00}

	// XFam specified processor features allowed inside of the TDs
	// Enable FP, SSE, AVX, AVX512, PK, and AMX
	expectedXfam := []byte{0xe7, 0x02, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00}

	valOpts := &validate.Options{
		HeaderOptions: validate.HeaderOptions{
			QeVendorID: IntelQeVendorID,
		},
		TdQuoteBodyOptions: validate.TdQuoteBodyOptions{
			MinimumTeeTcbSvn: expectedMinimumTeeTcbSvn,
			MrSeam:           nil, // Checked later
			TdAttributes:     expectedTdAttributes,
			Xfam:             expectedXfam,
			MrTd:             nil,              // Checked later
			MrConfigID:       make([]byte, 48), // All zeros
			MrOwner:          make([]byte, 48),
			MrOwnerConfig:    make([]byte, 48),
			Rtmrs:            nil, // Checked later
			ReportData:       nil, // Checked later
		},
	}

	if err := validate.TdxQuote(report, valOpts); err != nil {
		return nil, nil, err
	}

	// Validate MrSeam
	reportMrSeam := report.TdQuoteBody.MrSeam
	validMrSeam := false
	for _, mrSeam := range AcceptedMrSeams {
		if bytes.Equal(reportMrSeam, mrSeam) {
			validMrSeam = true
			break
		}
	}
	if !validMrSeam {
		return nil, nil, fmt.Errorf("No valid MrSeam found")
	}

	return registers, report.TdQuoteBody.ReportData, nil
}

func verifyTdxAttestationV2(attestationDoc string) (*Verification, error) {
	registers, reportData, err := verifyTdxReport(attestationDoc, true)
	if err != nil {
		return nil, err
	}

	return newVerificationV2(&Measurement{
		Type:      TdxGuestV2,
		Registers: registers,
	}, reportData), nil
}
