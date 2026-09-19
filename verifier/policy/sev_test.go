package policy

import (
	"encoding/json/v2"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSEVSNPPolicyRequiresExplicitBlocks(t *testing.T) {
	data, err := json.Marshal(validSEVSNPPolicy())
	require.NoError(t, err)
	for _, field := range []string{"guest_policy", "platform_info"} {
		for _, state := range []string{"missing", "null", "empty object"} {
			t.Run(field+"/"+state, func(t *testing.T) {
				var fields map[string]any
				require.NoError(t, json.Unmarshal(data, &fields))
				switch state {
				case "missing":
					delete(fields, field)
				case "null":
					fields[field] = nil
				case "empty object":
					fields[field] = map[string]any{}
				}
				wire, err := json.Marshal(fields)
				require.NoError(t, err)
				var p SEVSNPPolicy
				require.NoError(t, json.Unmarshal(wire, &p))
				if state == "empty object" {
					require.NoError(t, p.Validate()) // Explicit all-false expectations are valid.
				} else {
					require.ErrorContains(t, p.Validate(), field+" is required")
				}
			})
		}
	}
}

func TestSEVSNPPolicyValidateEncodedFields(t *testing.T) {
	p := validSEVSNPPolicy()
	assert.NoError(t, p.Validate())

	tests := []struct {
		name   string
		mutate func(*SEVSNPPolicy)
	}{
		{name: "malformed api version", mutate: func(p *SEVSNPPolicy) { p.MinimumAPIVersion = "1.2.3" }},
		{name: "version component overflow", mutate: func(p *SEVSNPPolicy) { p.MinimumABIVersion = "256.0" }},
		{name: "uppercase hex", mutate: func(p *SEVSNPPolicy) { p.HostData = strings.ToUpper(p.HostData) }},
		{name: "short hex", mutate: func(p *SEVSNPPolicy) { p.ImageID = p.ImageID[:len(p.ImageID)-2] }},
		{name: "non-hex", mutate: func(p *SEVSNPPolicy) { p.FamilyID = strings.Repeat("z", 32) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			bad := *p
			test.mutate(&bad)
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
		GuestPolicy:                    &GuestPolicy{},
		PlatformInfo:                   &SNPPlatform{},
		VMPL:                           &vmpl,
		HostData:                       strings.Repeat("ab", 32),
		ImageID:                        strings.Repeat("cd", 16),
		FamilyID:                       strings.Repeat("ef", 16),
		MinimumLaunchMitigationVector:  &minimumMitigationVector,
		MinimumCurrentMitigationVector: &minimumMitigationVector,
	}
}
