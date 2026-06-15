//go:build tinfoil_conformance

package attestation

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/go-tdx-guest/abi"
	pb "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/go-tdx-guest/validate"
	"github.com/google/go-tdx-guest/verify"
	"github.com/google/go-tdx-guest/verify/trust"
)

// TDXVerificationOptions lets conformance builds inject external dependencies
// while keeping normal production builds free of test hook API.
type TDXVerificationOptions struct {
	Getter           trust.HTTPSGetter
	TrustedRoots     *x509.CertPool
	Now              time.Time
	GetCollateral    *bool
	CheckRevocations *bool

	// Policy-baseline overrides. Production verification (tdx.go) hard-codes the
	// expected TD_ATTRIBUTES / XFAM / MinimumTeeTcbSvn / AcceptedMrSeams for the
	// real Tinfoil enclave. The cross-SDK conformance suite drives synthetic
	// vectors whose baseline differs, so the conformance binary re-baselines the
	// verifier to the vector's own values (mirroring tinfoil-python's
	// TdxVerificationConfig). When ExpectedTdAttributes is non-nil these replace
	// the hard-coded baseline; everything else (crypto, collateral, TCB-level
	// match) is unchanged go-tdx-guest logic.
	ExpectedTdAttributes     []byte
	ExpectedXfam             []byte
	ExpectedMinimumTeeTcbSvn []byte
	AcceptedMrSeams          [][]byte
}

// baselineOverridden reports whether the conformance binary supplied a
// re-baselined policy (public-api execution mode).
func (o *TDXVerificationOptions) baselineOverridden() bool {
	return o != nil && o.ExpectedTdAttributes != nil
}

// verifyTdxReportWithBaseline mirrors verifyTdxReportWithVerifyOptions
// (verifier/attestation/tdx.go) but takes the §4.8 policy baseline from the
// conformance options instead of the hard-coded production values. It runs the
// identical go-tdx-guest crypto + collateral + TCB-level verification
// (verify.TdxQuote) and policy validation (validate.TdxQuote); only the
// expected baseline values differ. Build-tagged: conformance-only.
func verifyTdxReportWithBaseline(attestationDoc string, isCompressed bool, opts *verify.Options, o *TDXVerificationOptions) ([]string, []byte, error) {
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
	if opts == nil {
		opts = defaultTdxVerifyOptions()
	}

	parsedReport, err := abi.QuoteToProto(attDocBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse report: %w", err)
	}
	report, ok := parsedReport.(*pb.QuoteV4)
	if !ok {
		return nil, nil, fmt.Errorf("failed to convert to QuoteV4")
	}

	// Crypto + collateral + TCB-level verification (unchanged go-tdx-guest).
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

	// Policy validation with the re-baselined expected values.
	valOpts := &validate.Options{
		HeaderOptions: validate.HeaderOptions{QeVendorID: IntelQeVendorID},
		TdQuoteBodyOptions: validate.TdQuoteBodyOptions{
			MinimumTeeTcbSvn: o.ExpectedMinimumTeeTcbSvn,
			TdAttributes:     o.ExpectedTdAttributes,
			Xfam:             o.ExpectedXfam,
			MrConfigID:       make([]byte, 48),
			MrOwner:          make([]byte, 48),
			MrOwnerConfig:    make([]byte, 48),
		},
	}
	if err := validate.TdxQuote(report, valOpts); err != nil {
		return nil, nil, err
	}

	// MrSeam allow-list (from the re-baselined options).
	validMrSeam := len(o.AcceptedMrSeams) == 0
	for _, mrSeam := range o.AcceptedMrSeams {
		if bytes.Equal(report.TdQuoteBody.MrSeam, mrSeam) {
			validMrSeam = true
			break
		}
	}
	if !validMrSeam {
		return nil, nil, fmt.Errorf("No valid MrSeam found")
	}

	return registers, report.TdQuoteBody.ReportData, nil
}

func (o *TDXVerificationOptions) verifyOptions() *verify.Options {
	opts := defaultTdxVerifyOptions()
	if o == nil {
		return opts
	}
	if o.Getter != nil {
		opts.Getter = o.Getter
	}
	if o.TrustedRoots != nil {
		opts.TrustedRoots = o.TrustedRoots
	}
	if !o.Now.IsZero() {
		opts.Now = o.Now
	}
	if o.GetCollateral != nil {
		opts.GetCollateral = *o.GetCollateral
	}
	if o.CheckRevocations != nil {
		opts.CheckRevocations = *o.CheckRevocations
	}
	return opts
}

func verifyTdxAttestationV2WithOptions(attestationDoc string, tdxOpts *TDXVerificationOptions) (*Verification, error) {
	var registers []string
	var reportData []byte
	var err error
	if tdxOpts.baselineOverridden() {
		registers, reportData, err = verifyTdxReportWithBaseline(attestationDoc, true, tdxOpts.verifyOptions(), tdxOpts)
	} else {
		registers, reportData, err = verifyTdxReportWithVerifyOptions(attestationDoc, true, tdxOpts.verifyOptions())
	}
	if err != nil {
		return nil, err
	}

	return newVerificationV2(&Measurement{
		Type:      TdxGuestV2,
		Registers: registers,
	}, reportData), nil
}

// VerifyWithTDXOptions checks a TDX attestation document with conformance-only
// dependency injection for collateral fetching, trusted roots, and time.
func (d *Document) VerifyWithTDXOptions(opts *TDXVerificationOptions) (*Verification, error) {
	if d.Format != TdxGuestV2 {
		return nil, fmt.Errorf("unsupported attestation format for TDX options: %s", d.Format)
	}
	return verifyTdxAttestationV2WithOptions(d.Body, opts)
}
