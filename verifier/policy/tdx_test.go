package policy

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTDXPolicyValidateHexFields(t *testing.T) {
	p := validTDXPolicy()
	assert.NoError(t, p.Validate())

	for name, mutate := range map[string]func(*TDXPolicy){
		"uppercase":  func(p *TDXPolicy) { p.QEVendorID = strings.ToUpper(p.QEVendorID) },
		"odd length": func(p *TDXPolicy) { p.MRSeam = p.MRSeam[:len(p.MRSeam)-1] },
		"non-hex":    func(p *TDXPolicy) { p.XFAM = strings.Repeat("z", 16) },
	} {
		t.Run(name, func(t *testing.T) {
			bad := *p
			mutate(&bad)
			assert.Error(t, bad.Validate())
		})
	}
}

func validTDXPolicy() *TDXPolicy {
	minimum := 0
	return &TDXPolicy{
		QEVendorID:                     strings.Repeat("ab", 16),
		MinimumTEETCBSVN:               strings.Repeat("00", 16),
		MRSeam:                         strings.Repeat("cd", 48),
		TDAttributes:                   strings.Repeat("00", 8),
		XFAM:                           strings.Repeat("00", 8),
		MinimumTCBEvaluationDataNumber: &minimum,
		PlatformMeasurements:           []string{"sample"},
	}
}
