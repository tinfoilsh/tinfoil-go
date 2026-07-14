package tdx

import (
	"encoding/hex"
	"fmt"

	tdxvalidate "github.com/google/go-tdx-guest/validate"

	"github.com/tinfoilsh/tinfoil-go/verifier/policy"
)

// CodeRegisters are the expected workload registers from code provenance.
// RTMR0 is a platform register and comes from the endorsed platform
// measurements instead.
type CodeRegisters struct {
	RTMR1 []byte
	RTMR2 []byte
	RTMR3 []byte
}

// Expectations is the fully translated TDX expected state: complete
// go-tdx-guest validation options plus the collateral floor, which is not a
// quote field. Validation performs no translation and no artifact lookups.
type Expectations struct {
	opts                           *tdxvalidate.Options
	minimumTCBEvaluationDataNumber int
}

// Assemble translates an endorsed policy block into the complete expected
// state for a quote. The endorsed platform measurement set is resolved to a
// single MRTD/RTMR0 by selection with the quote's authenticated registers —
// restricted to the required VM shape when one is declared — so a quote
// outside the endorsed set fails assembly; every register comparison then
// happens inside the library. The returned name identifies the resolved
// measurements-map entry.
func Assemble(a *policy.Artifact, p *policy.TDXPolicy, required *policy.Shape, q *Quote, code CodeRegisters, reportData [64]byte) (*Expectations, string, error) {
	opts, err := options(p)
	if err != nil {
		return nil, "", err
	}
	body := q.quote.GetTdQuoteBody()
	if body == nil || len(body.GetRtmrs()) != 4 {
		return nil, "", fmt.Errorf("TDX quote body must carry exactly 4 RTMRs")
	}

	name, m, err := a.ResolvePlatformMeasurement(p, required,
		hex.EncodeToString(body.GetMrTd()),
		hex.EncodeToString(body.GetRtmrs()[0]))
	if err != nil {
		return nil, "", err
	}
	mrtd, err := hex.DecodeString(m.MRTD)
	if err != nil {
		return nil, "", fmt.Errorf("platform measurement mrtd is not hex: %w", err)
	}
	rtmr0, err := hex.DecodeString(m.RTMR0)
	if err != nil {
		return nil, "", fmt.Errorf("platform measurement rtmr0 is not hex: %w", err)
	}
	opts.TdQuoteBodyOptions.MrTd = mrtd
	opts.TdQuoteBodyOptions.Rtmrs = [][]byte{rtmr0, code.RTMR1, code.RTMR2, code.RTMR3}
	opts.TdQuoteBodyOptions.ReportData = reportData[:]

	return &Expectations{
		opts:                           opts,
		minimumTCBEvaluationDataNumber: p.MinimumTCBEvaluationDataNumber,
	}, name, nil
}

// Validate compares a signature-verified quote against the assembled
// expected state: the library validation options plus the collateral
// tcbEvaluationDataNumber floor, which is not a quote field. It is the only
// TDX policy enforcement entry point so that no subset of the policy can be
// applied.
func (e *Expectations) Validate(q *Quote) error {
	if err := tdxvalidate.TdxQuote(q.quote, e.opts); err != nil {
		return err
	}
	if q.TCBEvaluationDataNumber < e.minimumTCBEvaluationDataNumber {
		return fmt.Errorf("tcbEvaluationDataNumber %d is below the policy minimum %d",
			q.TCBEvaluationDataNumber, e.minimumTCBEvaluationDataNumber)
	}
	return nil
}

// options translates the policy block into go-tdx-guest validation options.
// The tcbEvaluationDataNumber floor is not expressible in the library
// options and is enforced by the companion check composed in Validate.
func options(p *policy.TDXPolicy) (*tdxvalidate.Options, error) {
	qeVendor, err := hexField("qe_vendor_id", p.QEVendorID, 16)
	if err != nil {
		return nil, err
	}
	teeTcbSvn, err := hexField("minimum_tee_tcb_svn", p.MinimumTEETCBSVN, 16)
	if err != nil {
		return nil, err
	}
	mrSeam, err := hexField("mr_seam", p.MRSeam, 48)
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
			MrSeam:           mrSeam,
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
