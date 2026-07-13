package policy

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	sevabi "github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	"github.com/google/go-sev-guest/proto/sevsnp"
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
		VMPL: cloneIntPtr(p.VMPL),
	}, nil
}

// cloneIntPtr copies an optional int so assembled expectations do not alias
// the policy struct they were translated from.
func cloneIntPtr(v *int) *int {
	if v == nil {
		return nil
	}
	c := *v
	return &c
}

// SEVExpectations is the fully translated SEV-SNP expected state, resolved
// at policy assembly so that validation performs no translation.
type SEVExpectations struct {
	opts *sevvalidate.Options
}

// AssembleSEV translates the policy block into the complete expected state
// for the given product line. launchDigest is the expected 48-byte launch
// measurement from code provenance; nil leaves it unchecked for callers
// that compare it themselves.
func (p *SEVSNPPolicy) AssembleSEV(productLine string, launchDigest []byte) (*SEVExpectations, error) {
	opts, err := p.SEVOptions(productLine)
	if err != nil {
		return nil, err
	}
	opts.Measurement = launchDigest
	return &SEVExpectations{opts: opts}, nil
}

// Validate compares a signature-verified attestation against the assembled
// expected state. It is the only SEV policy enforcement entry point so that
// no subset of the policy can be applied.
func (e *SEVExpectations) Validate(attestation *sevsnp.Attestation) error {
	return sevvalidate.SnpAttestation(attestation, e.opts)
}

// TDXCodeRegisters are the expected workload registers from code
// provenance. RTMR0 is a platform register and comes from the endorsed
// platform measurements instead.
type TDXCodeRegisters struct {
	RTMR1 []byte
	RTMR2 []byte
	RTMR3 []byte
}

// TDXExpectations is the fully translated TDX expected state: complete
// go-tdx-guest validation options plus the collateral floor, which is not a
// quote field. Validation performs no translation and no artifact lookups.
type TDXExpectations struct {
	opts                           *tdxvalidate.Options
	minimumTCBEvaluationDataNumber int
}

// AssembleTDX translates the policy block into complete library validation
// options. The endorsed sets (accepted MR_SEAMs, allowed platform
// measurements) are resolved to single expected values by selection with
// the quote's authenticated registers, so a quote outside the endorsed sets
// fails assembly; every register comparison then happens inside the
// library.
func (a *Artifact) AssembleTDX(p *TDXPolicy, quote *tdxpb.QuoteV4, code TDXCodeRegisters) (*TDXExpectations, error) {
	opts, err := p.tdxOptions()
	if err != nil {
		return nil, err
	}
	body := quote.GetTdQuoteBody()
	if body == nil || len(body.GetRtmrs()) != 4 {
		return nil, fmt.Errorf("TDX quote body must carry exactly 4 RTMRs")
	}

	opts.TdQuoteBodyOptions.MrSeam, err = p.selectMRSeam(body.GetMrSeam())
	if err != nil {
		return nil, err
	}

	m, err := a.selectPlatformMeasurement(p,
		hex.EncodeToString(body.GetMrTd()),
		hex.EncodeToString(body.GetRtmrs()[0]))
	if err != nil {
		return nil, err
	}
	mrtd, err := hex.DecodeString(m.MRTD)
	if err != nil {
		return nil, fmt.Errorf("platform measurement mrtd is not hex: %w", err)
	}
	rtmr0, err := hex.DecodeString(m.RTMR0)
	if err != nil {
		return nil, fmt.Errorf("platform measurement rtmr0 is not hex: %w", err)
	}
	opts.TdQuoteBodyOptions.MrTd = mrtd
	opts.TdQuoteBodyOptions.Rtmrs = [][]byte{rtmr0, code.RTMR1, code.RTMR2, code.RTMR3}

	return &TDXExpectations{
		opts:                           opts,
		minimumTCBEvaluationDataNumber: p.MinimumTCBEvaluationDataNumber,
	}, nil
}

// selectMRSeam resolves the quote's authenticated MR_SEAM within the
// policy's accepted set.
func (p *TDXPolicy) selectMRSeam(mrSeam []byte) ([]byte, error) {
	for _, accepted := range p.AcceptedMRSeams {
		want, err := hex.DecodeString(accepted)
		if err != nil {
			return nil, fmt.Errorf("policy accepted_mr_seams entry is not hex: %w", err)
		}
		if bytes.Equal(mrSeam, want) {
			return want, nil
		}
	}
	return nil, fmt.Errorf("MR_SEAM %s is not in the policy's accepted set", hex.EncodeToString(mrSeam))
}

// selectPlatformMeasurement resolves the quote's authenticated MRTD/RTMR0
// within the platform measurements the policy allows.
func (a *Artifact) selectPlatformMeasurement(p *TDXPolicy, mrtdHex, rtmr0Hex string) (*PlatformMeasurement, error) {
	for _, ref := range p.PlatformMeasurements {
		m := a.Measurements[ref]
		if m.MRTD == mrtdHex && m.RTMR0 == rtmr0Hex {
			return &m, nil
		}
	}
	return nil, fmt.Errorf("platform measurements (mrtd %s...) do not match any allowed configuration", truncID(mrtdHex))
}

// Validate compares a signature-verified quote against the assembled
// expected state. tcbEvaluationDataNumber must come from the verified
// collateral (QE Identity / TCB Info) used during quote verification. It is
// the only TDX policy enforcement entry point so that no subset of the
// policy can be applied.
func (e *TDXExpectations) Validate(quote *tdxpb.QuoteV4, tcbEvaluationDataNumber int) error {
	if err := tdxvalidate.TdxQuote(quote, e.opts); err != nil {
		return err
	}
	if tcbEvaluationDataNumber < e.minimumTCBEvaluationDataNumber {
		return fmt.Errorf("tcbEvaluationDataNumber %d is below the policy minimum %d",
			tcbEvaluationDataNumber, e.minimumTCBEvaluationDataNumber)
	}
	return nil
}

// tdxOptions translates the policy block into go-tdx-guest validation
// options. MR_SEAM membership, the TCB evaluation data number, and platform
// measurement matching are not expressible in the library options and are
// enforced by the companion checks composed in TDXExpectations.Validate.
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
