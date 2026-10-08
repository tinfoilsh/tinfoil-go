package quote

import (
	"testing"

	tdxabi "github.com/google/go-tdx-guest/abi"
	"github.com/stretchr/testify/require"

	"github.com/tinfoilsh/tinfoil-go/internal/errs"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/policy"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/quote/sev"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/quote/tdx"
)

func TestMissingInputsAreConfigurationErrors(t *testing.T) {
	var config *errs.ConfigurationError
	_, err := Assemble(nil, CodeReferenceValues{}, nil, nil)
	require.ErrorAs(t, err, &config)
	_, err = assemble(nil, nil, [64]byte{}, nil)
	require.ErrorAs(t, err, &config)
	_, err = assemble(CodeReferenceValues{Endorsements: &policy.Artifact{}}, nil, [64]byte{}, &Authenticated{})
	require.ErrorAs(t, err, &config)
	_, err = sev.Assemble(&policy.SEVSNPPolicy{}, &sev.Quote{}, "", [64]byte{})
	require.ErrorAs(t, err, &config)
	_, err = tdx.Assemble(&policy.TDXPolicy{}, &tdx.Quote{}, [5]string{}, [64]byte{}, [tdxabi.MrConfigIDSize]byte{})
	require.ErrorAs(t, err, &config)
	for _, assembled := range []*AssembledPolicy{nil, {}} {
		require.ErrorAs(t, assembled.Validate(), &config)
	}
	for _, expected := range []*sev.Expectations{nil, {}} {
		require.ErrorAs(t, expected.Validate(nil), &config)
	}
	for _, expected := range []*tdx.Expectations{nil, {}} {
		require.ErrorAs(t, expected.Validate(nil), &config)
	}
}
