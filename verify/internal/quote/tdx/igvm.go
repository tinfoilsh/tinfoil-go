package tdx

import (
	"fmt"

	"github.com/tinfoilsh/tinfoil-go/verifier/internal/igvm"
	"github.com/tinfoilsh/tinfoil-go/verifier/internal/policy"
)

func AssembleIGVM(p *policy.TDXPolicy, runtime *igvm.TDXLaunch, configHash [32]byte, reportData [64]byte) (*Expectations, error) {
	if p == nil || p.ConfigBinding != policy.ConfigBindingSHA256 || runtime == nil {
		return nil, fmt.Errorf("IGVM requires runtime measurements and a config-binding platform policy")
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	opts, err := options(p)
	if err != nil {
		return nil, err
	}
	var decoded [5][]byte
	for i, value := range runtime.Registers() {
		decoded[i], err = policy.DecodeHex("runtime register", value, igvm.MeasurementSize)
		if err != nil {
			return nil, err
		}
	}
	opts.TdQuoteBodyOptions.MrTd = decoded[0]
	opts.TdQuoteBodyOptions.Rtmrs = decoded[1:]
	opts.TdQuoteBodyOptions.ReportData = reportData[:]
	copy(opts.TdQuoteBodyOptions.MrConfigID, configHash[:])
	return &Expectations{opts: opts, minimumTCBEvaluationDataNumber: *p.MinimumTCBEvaluationDataNumber}, nil
}
