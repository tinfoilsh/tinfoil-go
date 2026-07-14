package tdx

import (
	"encoding/hex"
	"fmt"

	tdxvalidate "github.com/google/go-tdx-guest/validate"

	"github.com/tinfoilsh/tinfoil-go/verifier/policy"
)

// CodeRegisters are the expected workload registers from code provenance;
// RTMR0 is a platform register and comes from the policy artifact instead.
type CodeRegisters struct {
	RTMR1 []byte
	RTMR2 []byte
	RTMR3 []byte
}

// Expectations is the fully translated TDX expected state, resolved at
// assembly so that validation performs no translation and no lookups. The
// collateral floor is separate because it is not a quote field.
type Expectations struct {
	opts                           *tdxvalidate.Options
	minimumTCBEvaluationDataNumber int
}

// Assemble translates a policy block into the complete expected state for
// a quote. The endorsed measurement set is resolved to a single MRTD/RTMR0
// by the quote's authenticated registers under the required VM shape, so a
// quote outside the endorsed set fails assembly; every register comparison
// then happens inside the library. The returned name is the resolved
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
		minimumTCBEvaluationDataNumber: *p.MinimumTCBEvaluationDataNumber,
	}, name, nil
}

// Validate compares a quote against the assembled expected state: the
// library validation options plus the collateral floor. It is the only TDX
// enforcement entry point, so no subset of the policy can be applied.
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
	return &tdxvalidate.Options{
		HeaderOptions: tdxvalidate.HeaderOptions{
			MinimumQeSvn:  *p.MinimumQESVN,
			MinimumPceSvn: *p.MinimumPCESVN,
			QeVendorID:    qeVendor,
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
