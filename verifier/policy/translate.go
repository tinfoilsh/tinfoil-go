package policy

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	sevabi "github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	sevvalidate "github.com/google/go-sev-guest/validate"
	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
	tdxvalidate "github.com/google/go-tdx-guest/validate"
)

// ProductGenoa is the only AMD product line currently supported by the
// verifier. Turin (family 1Ah) is not supported yet.
const ProductGenoa = "Genoa"

// SEVOptions translates the policy block into go-sev-guest validation
// options for the given product line. Only Genoa (family 19h) is supported.
func (p *SEVSNPPolicy) SEVOptions(productLine string) (*sevvalidate.Options, error) {
	if productLine != ProductGenoa {
		return nil, fmt.Errorf("unsupported SEV product line %q (only %s is supported)", productLine, ProductGenoa)
	}
	version, err := parseAPIVersion(p.MinimumAPIVersion)
	if err != nil {
		return nil, err
	}
	if p.MinimumTCB.FmcSpl != nil || p.MinimumLaunchTCB.FmcSpl != nil {
		return nil, fmt.Errorf("fmc_spl is not valid for product line %s", productLine)
	}

	return &sevvalidate.Options{
		GuestPolicy: sevabi.SnpPolicy{
			Debug:        p.GuestPolicy.Debug,
			SMT:          p.GuestPolicy.SMT,
			MigrateMA:    p.GuestPolicy.MigrateMA,
			SingleSocket: p.GuestPolicy.SingleSocket,
		},
		MinimumGuestSvn:           p.MinimumGuestSVN,
		MinimumBuild:              p.MinimumBuild,
		MinimumVersion:            version,
		PermitProvisionalFirmware: p.PermitProvisionalFirmware,
		PlatformInfo: &sevabi.SnpPlatformInfo{
			SMTEnabled:                  p.PlatformInfo.SMTEnabled,
			TSMEEnabled:                 p.PlatformInfo.TSMEEnabled,
			ECCEnabled:                  p.PlatformInfo.ECCEnabled,
			RAPLDisabled:                p.PlatformInfo.RAPLDisabled,
			CiphertextHidingDRAMEnabled: p.PlatformInfo.CiphertextHidingDRAM,
		},
		MinimumTCB: kds.TCBParts{
			BlSpl:    p.MinimumTCB.BlSpl,
			TeeSpl:   p.MinimumTCB.TeeSpl,
			SnpSpl:   p.MinimumTCB.SnpSpl,
			UcodeSpl: p.MinimumTCB.UcodeSpl,
		},
		MinimumLaunchTCB: kds.TCBParts{
			BlSpl:    p.MinimumLaunchTCB.BlSpl,
			TeeSpl:   p.MinimumLaunchTCB.TeeSpl,
			SnpSpl:   p.MinimumLaunchTCB.SnpSpl,
			UcodeSpl: p.MinimumLaunchTCB.UcodeSpl,
		},
		VMPL: p.VMPL,
	}, nil
}

// ValidateTDXQuote enforces the complete TDX policy against a quote:
// go-tdx-guest validation options plus the checks not expressible in those
// options (MR_SEAM membership, the collateral's tcbEvaluationDataNumber, and
// MRTD/RTMR0 platform measurement matching). It is the only policy
// enforcement entry point so that no subset of the policy can be applied.
//
// The quote's signature chain must already have been verified (go-tdx-guest
// verify.TdxQuote); tcbEvaluationDataNumber must come from the verified
// collateral (QE Identity / TCB Info) used during that verification.
func (a *Artifact) ValidateTDXQuote(p *TDXPolicy, quote *tdxpb.QuoteV4, tcbEvaluationDataNumber int) error {
	opts, err := p.tdxOptions()
	if err != nil {
		return err
	}
	// tdxvalidate.TdxQuote runs abi.CheckQuoteV4 first, which guarantees the
	// TD quote body exists with 48-byte MRTD and exactly 4 48-byte RTMRs.
	if err := tdxvalidate.TdxQuote(quote, opts); err != nil {
		return err
	}
	if err := p.checkTCBEvaluationDataNumber(tcbEvaluationDataNumber); err != nil {
		return err
	}
	body := quote.GetTdQuoteBody()
	if err := p.checkMRSeam(body.GetMrSeam()); err != nil {
		return err
	}
	return a.checkPlatformMeasurement(p,
		hex.EncodeToString(body.GetMrTd()),
		hex.EncodeToString(body.GetRtmrs()[0]))
}

// tdxOptions translates the policy block into go-tdx-guest validation
// options. MR_SEAM membership, the TCB evaluation data number, and platform
// measurement matching are not expressible in the library options and are
// enforced by the companion checks composed in ValidateTDXQuote.
func (p *TDXPolicy) tdxOptions() (*tdxvalidate.Options, error) {
	qeVendor, err := hexField("qe_vendor_id", p.QEVendorID, 16)
	if err != nil {
		return nil, err
	}
	teeTcbSvn, err := hexField("minimum_tee_tcb_svn", p.MinimumTEETCBSVN, 16)
	if err != nil {
		return nil, err
	}
	tdAttributes, err := hexField("td_attributes", p.TDAttributes, 8)
	if err != nil {
		return nil, err
	}
	xfam, err := hexField("xfam", p.XFAM, 8)
	if err != nil {
		return nil, err
	}

	opts := &tdxvalidate.Options{
		HeaderOptions: tdxvalidate.HeaderOptions{
			MinimumQeSvn:  p.MinimumQESVN,
			MinimumPceSvn: p.MinimumPCESVN,
			QeVendorID:    qeVendor,
		},
		TdQuoteBodyOptions: tdxvalidate.TdQuoteBodyOptions{
			MinimumTeeTcbSvn: teeTcbSvn,
			TdAttributes:     tdAttributes,
			Xfam:             xfam,
		},
	}
	if p.MRConfigIDZero {
		opts.TdQuoteBodyOptions.MrConfigID = make([]byte, 48)
	}
	if p.MROwnerZero {
		opts.TdQuoteBodyOptions.MrOwner = make([]byte, 48)
	}
	if p.MROwnerConfigZero {
		opts.TdQuoteBodyOptions.MrOwnerConfig = make([]byte, 48)
	}
	return opts, nil
}

// checkTCBEvaluationDataNumber verifies that collateral (QE Identity or TCB
// Info) meets the policy's minimum tcbEvaluationDataNumber.
func (p *TDXPolicy) checkTCBEvaluationDataNumber(n int) error {
	if n < p.MinimumTCBEvaluationDataNumber {
		return fmt.Errorf("tcbEvaluationDataNumber %d is below the policy minimum %d",
			n, p.MinimumTCBEvaluationDataNumber)
	}
	return nil
}

// checkMRSeam verifies membership of the quote's MR_SEAM in the policy's
// accepted set.
func (p *TDXPolicy) checkMRSeam(mrSeam []byte) error {
	for _, accepted := range p.AcceptedMRSeams {
		want, err := hex.DecodeString(accepted)
		if err != nil {
			return fmt.Errorf("policy accepted_mr_seams entry is not hex: %w", err)
		}
		if bytes.Equal(mrSeam, want) {
			return nil
		}
	}
	return fmt.Errorf("MR_SEAM %s is not in the policy's accepted set", hex.EncodeToString(mrSeam))
}

// checkPlatformMeasurement verifies the quote's MRTD/RTMR0 against the
// platform measurements the policy allows, resolved through the artifact.
func (a *Artifact) checkPlatformMeasurement(p *TDXPolicy, mrtdHex, rtmr0Hex string) error {
	for _, ref := range p.PlatformMeasurements {
		m := a.Measurements[ref]
		if m.MRTD == mrtdHex && m.RTMR0 == rtmr0Hex {
			return nil
		}
	}
	return fmt.Errorf("platform measurements (mrtd %s...) do not match any allowed configuration", truncID(mrtdHex))
}

func parseAPIVersion(v string) (uint16, error) {
	major, minor, found := strings.Cut(v, ".")
	if !found {
		return 0, fmt.Errorf("minimum_api_version %q is not maj.min", v)
	}
	maj, err := strconv.ParseUint(major, 10, 8)
	if err != nil {
		return 0, fmt.Errorf("minimum_api_version major: %w", err)
	}
	min, err := strconv.ParseUint(minor, 10, 8)
	if err != nil {
		return 0, fmt.Errorf("minimum_api_version minor: %w", err)
	}
	return uint16(maj<<8 | min), nil
}

func hexField(name, value string, wantLen int) ([]byte, error) {
	b, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("%s is not hex: %w", name, err)
	}
	if len(b) != wantLen {
		return nil, fmt.Errorf("%s must be %d bytes, got %d", name, wantLen, len(b))
	}
	return b, nil
}
