package sev

import (
	"encoding/hex"
	"fmt"

	"github.com/tinfoilsh/tinfoil-go/verifier/internal/igvm"
	"github.com/tinfoilsh/tinfoil-go/verifier/internal/policy"
)

func AssembleIGVM(p *policy.SEVSNPPolicy, q *Quote, runtime *igvm.SNPLaunch, configHash [32]byte, reportData [64]byte) (*Expectations, error) {
	if p == nil || p.ConfigBinding != policy.ConfigBindingSHA256 || runtime == nil {
		return nil, fmt.Errorf("IGVM requires runtime measurements and a config-binding platform policy")
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	guestPolicy, err := runtime.PolicyValue()
	if err != nil {
		return nil, err
	}
	if runtime.GuestSVN == nil || *runtime.GuestSVN != 0 {
		return nil, fmt.Errorf("IGVM v1 requires zero guest SVN")
	}
	resolved := *p
	resolved.ConfigBinding = ""
	resolved.HostData = hex.EncodeToString(configHash[:])
	expected, err := Assemble(&resolved, q, runtime.Measurement, reportData)
	if err != nil {
		return nil, err
	}
	expected.runtimeGuestPolicy = &guestPolicy
	return expected, nil
}
