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
	registers, reportData, err := verifyTdxReportWithVerifyOptions(attestationDoc, true, tdxOpts.verifyOptions())
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
