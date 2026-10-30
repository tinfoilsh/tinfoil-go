//go:build tinfoil_conformance

package attestation

import (
	"crypto/x509"
	"fmt"
	"time"

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

// verifyTdxReportWithBaseline is the production verification flow with the
// vector's own §4.8 baseline injected. Build-tagged: conformance-only.
func verifyTdxReportWithBaseline(attestationDoc string, isCompressed bool, opts *verify.Options, o *TDXVerificationOptions) ([]string, []byte, error) {
	return verifyTdxReportWithPolicy(attestationDoc, isCompressed, opts, &tdxPolicyBaseline{
		MinimumTeeTcbSvn: o.ExpectedMinimumTeeTcbSvn,
		AcceptedMrSeams:  o.AcceptedMrSeams,
		TdAttributes:     o.ExpectedTdAttributes,
		Xfam:             o.ExpectedXfam,
	})
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
