package quote

import (
	"testing"

	tdxabi "github.com/google/go-tdx-guest/abi"
	"github.com/stretchr/testify/require"

	"github.com/tinfoilsh/tinfoil-go/verify/internal/errs"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/policy"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/quote/sev"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/quote/tdx"
)

func TestMissingInputsAreUsageErrors(t *testing.T) {
	var usage *errs.UsageError
	_, err := Assemble(nil, LegacyReferenceValues{}, nil, nil)
	require.ErrorAs(t, err, &usage)
	_, err = assemble(nil, nil, [64]byte{}, nil)
	require.ErrorAs(t, err, &usage)
	_, err = assemble(LegacyReferenceValues{Endorsements: &policy.Artifact{}}, nil, [64]byte{}, &Authenticated{})
	require.ErrorAs(t, err, &usage)
	_, err = sev.Assemble(&policy.SEVSNPPolicy{}, &sev.Quote{}, "", [64]byte{})
	require.ErrorAs(t, err, &usage)
	_, err = tdx.Assemble(&policy.TDXPolicy{}, &tdx.Quote{}, [5]string{}, [64]byte{}, [tdxabi.MrConfigIDSize]byte{})
	require.ErrorAs(t, err, &usage)
	for _, assembled := range []*AssembledPolicy{nil, {}} {
		require.ErrorAs(t, assembled.Validate(), &usage)
	}
	for _, expected := range []*sev.Expectations{nil, {}} {
		require.ErrorAs(t, expected.Validate(nil), &usage)
	}
	for _, expected := range []*tdx.Expectations{nil, {}} {
		require.ErrorAs(t, expected.Validate(nil), &usage)
	}
}
