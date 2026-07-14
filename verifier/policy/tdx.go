package policy

import "fmt"

// TDXPolicy is the standard Intel TDX policy block. PlatformMeasurements
// names the measurements-map entries the machine is endorsed to run; the
// quote's own MRTD/RTMR0 select exactly one of them at policy assembly.
// Numeric members are pointers so parsing can tell an absent member from a
// meaningful zero — Validate rejects any absent member.
type TDXPolicy struct {
	QEVendorID                     string   `json:"qe_vendor_id"`
	MinimumQESVN                   *uint16  `json:"minimum_qe_svn"`
	MinimumPCESVN                  *uint16  `json:"minimum_pce_svn"`
	MinimumTEETCBSVN               string   `json:"minimum_tee_tcb_svn"`
	MRSeam                         string   `json:"mr_seam"`
	TDAttributes                   string   `json:"td_attributes"`
	XFAM                           string   `json:"xfam"`
	MinimumTCBEvaluationDataNumber *int     `json:"minimum_tcb_evaluation_data_number"`
	PlatformMeasurements           []string `json:"platform_measurements"`
}

// Validate rejects a block with any absent or malformed required member.
func (p *TDXPolicy) Validate() error {
	switch {
	case p.MinimumQESVN == nil:
		return fmt.Errorf("minimum_qe_svn is required")
	case p.MinimumPCESVN == nil:
		return fmt.Errorf("minimum_pce_svn is required")
	case p.MinimumTCBEvaluationDataNumber == nil:
		return fmt.Errorf("minimum_tcb_evaluation_data_number is required")
	case *p.MinimumTCBEvaluationDataNumber < 0:
		// A negative minimum would pass for any collateral, silently
		// disabling the freshness floor.
		return fmt.Errorf("minimum_tcb_evaluation_data_number must not be negative")
	case len(p.PlatformMeasurements) == 0:
		return fmt.Errorf("platform_measurements must not be empty")
	}
	return nil
}
