package policy

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSEVSNPPolicyValidateEncodedFields(t *testing.T) {
	p := validSEVSNPPolicy()
	assert.NoError(t, p.Validate())

	for name, mutate := range map[string]func(*SEVSNPPolicy){
		"malformed api version":      func(p *SEVSNPPolicy) { p.MinimumAPIVersion = "1.2.3" },
		"version component overflow": func(p *SEVSNPPolicy) { p.MinimumABIVersion = "256.0" },
		"uppercase hex":              func(p *SEVSNPPolicy) { p.HostData = strings.ToUpper(p.HostData) },
		"short hex":                  func(p *SEVSNPPolicy) { p.ImageID = p.ImageID[:len(p.ImageID)-2] },
		"non-hex":                    func(p *SEVSNPPolicy) { p.FamilyID = strings.Repeat("z", 32) },
	} {
		t.Run(name, func(t *testing.T) {
			bad := *p
			mutate(&bad)
			assert.Error(t, bad.Validate())
		})
	}
}

func validSEVSNPPolicy() *SEVSNPPolicy {
	minimumBuild := uint8(0)
	minimumGuestSVN := uint32(0)
	vmpl := 0
	minimumMitigationVector := uint64(0)
	tcbPart := uint8(0)
	tcb := TCB{BlSpl: &tcbPart, TeeSpl: &tcbPart, SnpSpl: &tcbPart, UcodeSpl: &tcbPart}
	return &SEVSNPPolicy{
		MinimumBuild:                   &minimumBuild,
		MinimumAPIVersion:              "1.55",
		MinimumABIVersion:              "0.31",
		MinimumGuestSVN:                &minimumGuestSVN,
		MinimumTCB:                     tcb,
		MinimumLaunchTCB:               tcb,
		VMPL:                           &vmpl,
		HostData:                       strings.Repeat("ab", 32),
		ImageID:                        strings.Repeat("cd", 16),
		FamilyID:                       strings.Repeat("ef", 16),
		MinimumLaunchMitigationVector:  &minimumMitigationVector,
		MinimumCurrentMitigationVector: &minimumMitigationVector,
	}
}
