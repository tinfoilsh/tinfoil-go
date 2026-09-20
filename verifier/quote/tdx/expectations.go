package tdx

import (
	"cmp"
	"encoding/hex"
	"fmt"

	tdxvalidate "github.com/google/go-tdx-guest/validate"

	"github.com/tinfoilsh/tinfoil-go/verifier/measurement"
	"github.com/tinfoilsh/tinfoil-go/verifier/policy"
)

// Expectations holds TDX validation options and the collateral TCB floor.
type Expectations struct {
	opts                           *tdxvalidate.Options
	minimumTCBEvaluationDataNumber int
}

// Assemble requires the quote's MRTD/RTMR0 to match an endorsed measurement for
// the required VM shape, then builds validation options from policy and registers.
// It returns the matching measurements-map entry's name.
func Assemble(a *policy.Artifact, p *policy.TDXPolicy, required *policy.Shape, q *Quote, registers [5]string, reportData [64]byte) (*Expectations, string, error) {
	opts, err := options(p)
	if err != nil {
		return nil, "", err
	}
	body := q.quote.GetTdQuoteBody()
	name, m, err := a.ResolvePlatformMeasurement(p, required,
		hex.EncodeToString(body.GetMrTd()),
		hex.EncodeToString(body.GetRtmrs()[0]))
	if err != nil {
		return nil, "", err
	}
	registers[0] = cmp.Or(registers[0], m.MRTD)
	registers[1] = cmp.Or(registers[1], m.RTMR0)
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

// Validate checks quote fields and the collateral TCB floor.
func (e *Expectations) Validate(q *Quote) error {
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

	// MR_CONFIG_ID, MR_OWNER, and MR_OWNER_CONFIG are unconditionally
	// pinned to zero: Tinfoil launches never populate them.
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
			MrConfigID:       make([]byte, 48),
			MrOwner:          make([]byte, 48),
			MrOwnerConfig:    make([]byte, 48),
		},
	}, nil
}
