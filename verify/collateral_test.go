package verify

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/verify/document/collateral"
)

func TestCollateralCheckRejectsInvalidProfilesAndConflictingTrust(t *testing.T) {
	var missing *Verifier
	_, err := missing.CheckCollateral(CollateralCheck{})
	require.ErrorAs(t, err, new(*UsageError))
	v, err := NewVerifier()
	require.NoError(t, err)
	for _, candidate := range []CollateralCheck{
		{Format: "unknown"},
		{Format: collateral.FormatV2, Runtime: &collateral.RuntimeReference{}},
		{Format: collateral.FormatV3, Runtime: &collateral.RuntimeReference{}, Reference: "org/repo"},
		{Format: collateral.FormatV3, Runtime: &collateral.RuntimeReference{}},
	} {
		result, err := v.CheckCollateral(candidate)
		require.Error(t, err)
		require.Nil(t, result)
	}
	inputs := embeddedInputs(t)
	v, err = NewVerifier(WithEmbeddedReferences(inputs))
	require.NoError(t, err)
	result, err := v.CheckCollateral(CollateralCheck{
		Format:  collateral.FormatV3,
		Runtime: &collateral.RuntimeReference{Repo: collateral.RuntimeRepo, Tag: "v0.15.0", Digest: strings.Repeat("ab", 32)},
	})
	require.ErrorContains(t, err, "without config or workload trust")
	require.Nil(t, result)
}
