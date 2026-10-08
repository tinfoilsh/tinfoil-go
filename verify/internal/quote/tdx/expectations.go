package tdx

import (
	"fmt"

	tdxabi "github.com/google/go-tdx-guest/abi"
	tdxvalidate "github.com/google/go-tdx-guest/validate"

	"github.com/tinfoilsh/tinfoil-go/internal/errs"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/policy"
)

// Expectations is the fully translated TDX expected state, resolved at
// assembly so that validation performs no translation and no lookups. The
// collateral floor is separate because it is not a quote field.
type Expectations struct {
	opts                           *tdxvalidate.Options
	minimumTCBEvaluationDataNumber int
}

// Assemble translates complete reference values into vendor validation options.
func Assemble(p *policy.TDXPolicy, q *Quote, registers [5]string, reportData [64]byte, configID [tdxabi.MrConfigIDSize]byte) (result *Expectations, err error) {
	defer func() { err = errs.WrapAttestation(err) }()
	if p == nil {
		return nil, &errs.ConfigurationError{Err: fmt.Errorf("TDX policy is required")}
	}
	if q == nil || q.quote == nil {
		return nil, &errs.ConfigurationError{Err: fmt.Errorf("authenticated TDX quote is required")}
	}
	opts, err := options(p)
	if err != nil {
		return nil, err
	}
	copy(opts.TdQuoteBodyOptions.MrConfigID, configID[:])
	var decoded [5][]byte
	registerSizes := [5]int{tdxabi.MrTdSize, tdxabi.RtmrSize, tdxabi.RtmrSize, tdxabi.RtmrSize, tdxabi.RtmrSize}
	for i, label := range [5]string{"mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3"} {
		if decoded[i], err = policy.DecodeHex(label, registers[i], registerSizes[i]); err != nil {
			return nil, err
		}
	}
	opts.TdQuoteBodyOptions.MrTd = decoded[0]
	opts.TdQuoteBodyOptions.Rtmrs = decoded[1:]
	opts.TdQuoteBodyOptions.ReportData = reportData[:]

	return &Expectations{
		opts:                           opts,
		minimumTCBEvaluationDataNumber: *p.MinimumTCBEvaluationDataNumber,
	}, nil
}

// Validate compares a quote against the assembled expected state: the
// library validation options plus the collateral floor. It is the only TDX
// enforcement entry point, so no subset of the policy can be applied.
func (e *Expectations) Validate(q *Quote) (err error) {
	defer func() { err = errs.WrapAttestation(err) }()
	if e == nil || e.opts == nil {
		return &errs.ConfigurationError{Err: fmt.Errorf("assembled TDX expectations are required")}
	}
	if q == nil || q.quote == nil {
		return &errs.ConfigurationError{Err: fmt.Errorf("authenticated TDX quote is required")}
	}
	if err := tdxvalidate.TdxQuote(q.quote, e.opts); err != nil {
		return err
	}
	if q.tcbEvaluationDataNumber < e.minimumTCBEvaluationDataNumber {
		return fmt.Errorf("tcbEvaluationDataNumber %d is below the policy minimum %d",
			q.tcbEvaluationDataNumber, e.minimumTCBEvaluationDataNumber)
	}
	return nil
}

// options translates the policy block into library validation options.
func options(p *policy.TDXPolicy) (*tdxvalidate.Options, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	qeVendor, err := policy.DecodeHex("qe_vendor_id", p.QEVendorID, tdxabi.QeVendorIDSize)
	if err != nil {
		return nil, err
	}
	teeTcbSvn, err := policy.DecodeHex("minimum_tee_tcb_svn", p.MinimumTEETCBSVN, tdxabi.TeeTcbSvnSize)
	if err != nil {
		return nil, err
	}
	mrSeam, err := policy.DecodeHex("mr_seam", p.MRSeam, tdxabi.MrSeamSize)
	if err != nil {
		return nil, err
	}
	tdAttributes, err := policy.DecodeHex("td_attributes", p.TDAttributes, tdxabi.TdAttributesSize)
	if err != nil {
		return nil, err
	}
	xfam, err := policy.DecodeHex("xfam", p.XFAM, tdxabi.XfamSize)
	if err != nil {
		return nil, err
	}

	// MR_OWNER and MR_OWNER_CONFIG are pinned to zero. MR_CONFIG_ID is
	// resolved by the verification profile, with zero as the legacy expectation.
	// The QE and PCE security versions are enforced by quote verification
	// against Intel's signed QE Identity and TCB Info collateral; the
	// library's header minimums compare reserved header bytes (pinned to
	// zero at authentication) and are left unset.
	return &tdxvalidate.Options{
		HeaderOptions: tdxvalidate.HeaderOptions{
			QeVendorID: qeVendor,
		},
		TdQuoteBodyOptions: tdxvalidate.TdQuoteBodyOptions{
			MinimumTeeTcbSvn: teeTcbSvn,
			MrSeam:           mrSeam,
			TdAttributes:     tdAttributes,
			Xfam:             xfam,
			MrConfigID:       make([]byte, tdxabi.MrConfigIDSize),
			MrOwner:          make([]byte, tdxabi.MrOwnerSize),
			MrOwnerConfig:    make([]byte, tdxabi.MrOwnerConfigSize),
		},
	}, nil
}
