package tdx

import (
	"cmp"
	"encoding/hex"
	"fmt"

	tdxvalidate "github.com/google/go-tdx-guest/validate"

	"github.com/tinfoilsh/tinfoil-go/internal/errs"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/policy"
	"github.com/tinfoilsh/tinfoil-go/verify/measurement"
)

// Expectations is the fully translated TDX expected state, resolved at
// assembly so that validation performs no translation and no lookups. The
// collateral floor is separate because it is not a quote field.
type Expectations struct {
	opts                           *tdxvalidate.Options
	minimumTCBEvaluationDataNumber int
}

// Assemble requires the quote's MRTD/RTMR0 to match an endorsed measurement for
// the required VM shape, then builds validation options from policy and registers.
// It returns the matching measurements-map entry's name.
func Assemble(a *policy.Artifact, p *policy.TDXPolicy, required *policy.Shape, q *Quote, registers [5]string, reportData [64]byte) (result *Expectations, name string, err error) {
	defer func() { err = errs.WrapAttestation(err) }()
	if a == nil || p == nil {
		return nil, "", &errs.ConfigurationError{Err: fmt.Errorf("endorsements and TDX policy are required")}
	}
	if q == nil || q.quote == nil {
		return nil, "", &errs.ConfigurationError{Err: fmt.Errorf("authenticated TDX quote is required")}
	}
	opts, err := options(p)
	if err != nil {
		return nil, "", err
	}
	// An image supplying all five registers itself needs no measurements-map
	// entry and no VM shape.
	if len(p.PlatformMeasurements) > 0 {
		if required == nil {
			// Reachable from collateral, so it is the document's fault and
			// not the caller's.
			return nil, "", fmt.Errorf("policy enumerates platform measurements but the reference values declare no VM shape")
		}
		body := q.quote.GetTdQuoteBody()
		var m *policy.PlatformMeasurement
		name, m, err = a.ResolvePlatformMeasurement(p, required,
			hex.EncodeToString(body.GetMrTd()),
			hex.EncodeToString(body.GetRtmrs()[0]))
		if err != nil {
			return nil, "", err
		}
		registers[0] = cmp.Or(registers[0], m.MRTD)
		registers[1] = cmp.Or(registers[1], m.RTMR0)
	} else if registers[0] == "" || registers[1] == "" {
		// A policy naming no platform measurement expects reference values
		// that fix MRTD and RTMR0 themselves.
		return nil, "", fmt.Errorf("policy names no platform measurement and the reference values supply no MRTD or RTMR0")
	}
	registers[4] = cmp.Or(registers[4], measurement.RTMR3_ZERO)
	var decoded [5][]byte
	for i, label := range [5]string{"mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3"} {
		if decoded[i], err = policy.DecodeHex(label, registers[i], 48); err != nil {
			return nil, "", err
		}
	}
	opts.TdQuoteBodyOptions.MrTd = decoded[0]
	opts.TdQuoteBodyOptions.Rtmrs = decoded[1:]
	opts.TdQuoteBodyOptions.ReportData = reportData[:]

	return &Expectations{
		opts:                           opts,
		minimumTCBEvaluationDataNumber: *p.MinimumTCBEvaluationDataNumber,
	}, name, nil
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
	if p.ConfigBinding != "" {
		return nil, fmt.Errorf("policy declares config_binding %q and was never resolved against a config", p.ConfigBinding)
	}
	qeVendor, err := policy.DecodeHex("qe_vendor_id", p.QEVendorID, 16)
	if err != nil {
		return nil, err
	}
	teeTcbSvn, err := policy.DecodeHex("minimum_tee_tcb_svn", p.MinimumTEETCBSVN, 16)
	if err != nil {
		return nil, err
	}
	mrSeam, err := policy.DecodeHex("mr_seam", p.MRSeam, 48)
	if err != nil {
		return nil, err
	}
	tdAttributes, err := policy.DecodeHex("td_attributes", p.TDAttributes, 8)
	if err != nil {
		return nil, err
	}
	xfam, err := policy.DecodeHex("xfam", p.XFAM, 8)
	if err != nil {
		return nil, err
	}

	// MR_OWNER and MR_OWNER_CONFIG are pinned to zero: Tinfoil launches never
	// populate them. MR_CONFIG_ID is too, unless a config binding set it.
	mrConfigID := make([]byte, 48)
	if p.MRConfigID != "" {
		if mrConfigID, err = policy.DecodeHex("mr_config_id", p.MRConfigID, 48); err != nil {
			return nil, err
		}
	}
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
			MrConfigID:       mrConfigID,
			MrOwner:          make([]byte, 48),
			MrOwnerConfig:    make([]byte, 48),
		},
	}, nil
}
