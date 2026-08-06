package policy

import (
	"fmt"
	"strings"
)

// TDXPolicy is the standard Intel TDX policy block. PlatformMeasurements
// names the measurements-map entries the machine is endorsed to run; the
// quote's own MRTD/RTMR0 select exactly one of them at policy assembly.
// Numeric members are pointers so parsing can tell an absent member from a
// meaningful zero — Validate rejects any absent member.
type TDXPolicy struct {
	QEVendorID                     string   `json:"qe_vendor_id"`
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
	case p.QEVendorID == "":
		return fmt.Errorf("qe_vendor_id is required")
	case p.MinimumTEETCBSVN == "":
		return fmt.Errorf("minimum_tee_tcb_svn is required")
	case p.MRSeam == "":
		return fmt.Errorf("mr_seam is required")
	case p.TDAttributes == "":
		return fmt.Errorf("td_attributes is required")
	case p.XFAM == "":
		return fmt.Errorf("xfam is required")
	case p.MinimumTCBEvaluationDataNumber == nil:
		return fmt.Errorf("minimum_tcb_evaluation_data_number is required")
	case *p.MinimumTCBEvaluationDataNumber < 0:
		// A negative minimum would pass for any collateral, silently
		// disabling the freshness floor.
		return fmt.Errorf("minimum_tcb_evaluation_data_number must not be negative")
	case len(p.PlatformMeasurements) == 0:
		return fmt.Errorf("platform_measurements must not be empty")
	}
	for name, field := range map[string]struct {
		value   string
		byteLen int
	}{
		"qe_vendor_id":        {p.QEVendorID, 16},
		"minimum_tee_tcb_svn": {p.MinimumTEETCBSVN, 16},
		"mr_seam":             {p.MRSeam, 48},
		"td_attributes":       {p.TDAttributes, 8},
		"xfam":                {p.XFAM, 8},
	} {
		if err := validatePolicyHex(name, field.value, field.byteLen); err != nil {
			return err
		}
	}
	return nil
}

func validatePolicyHex(name, value string, byteLen int) error {
	if value != strings.ToLower(value) {
		return fmt.Errorf("%s must be lowercase hex", name)
	}
	_, err := DecodeHex(name, value, byteLen)
	return err
}
