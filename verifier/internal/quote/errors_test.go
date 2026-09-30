package quote

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/tinfoilsh/tinfoil-go/verifier/internal/errs"
	"github.com/tinfoilsh/tinfoil-go/verifier/internal/policy"
	"github.com/tinfoilsh/tinfoil-go/verifier/internal/quote/sev"
	"github.com/tinfoilsh/tinfoil-go/verifier/internal/quote/tdx"
)

func TestMissingInputsAreConfigurationErrors(t *testing.T) {
	var config *errs.ConfigurationError
	_, err := Assemble(nil, nil, nil, nil, nil, nil)
	require.ErrorAs(t, err, &config)
	_, err = assemble(nil, nil, nil, nil, [64]byte{}, nil)
	require.ErrorAs(t, err, &config)
	_, err = assemble(&policy.Artifact{}, nil, nil, nil, [64]byte{}, &Authenticated{})
	require.ErrorAs(t, err, &config)
	_, err = sev.Assemble(&policy.SEVSNPPolicy{}, &sev.Quote{}, "", [64]byte{})
	require.ErrorAs(t, err, &config)
	_, _, err = tdx.Assemble(&policy.Artifact{}, &policy.TDXPolicy{}, &policy.Shape{}, &tdx.Quote{}, [5]string{}, [64]byte{})
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
