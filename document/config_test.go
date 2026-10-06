package document

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/document/collateral"
)

func TestConfigCollateralAccessorsReturnCopies(t *testing.T) {
	doc := &Document{collateral: collateral.Set{
		Config:  &collateral.ConfigEndorsement{Reference: "ref", Config: []byte("config"), Bundle: []byte(`{}`)},
		Runtime: &collateral.IGVMRuntime{Manifest: []byte("manifest"), Bundle: []byte(`{}`)},
	}}
	config, err := doc.ConfigEndorsement()
	require.NoError(t, err)
	config.Reference = "changed"
	config.Config[0] = '!'
	config.Bundle[0] = '!'
	againConfig, err := doc.ConfigEndorsement()
	require.NoError(t, err)
	require.Equal(t, "ref", againConfig.Reference)
	require.Equal(t, "config", string(againConfig.Config))
	require.Equal(t, "{}", string(againConfig.Bundle))

	runtime, err := doc.IGVMRuntime()
	require.NoError(t, err)
	runtime.Manifest[0] = '!'
	runtime.Bundle[0] = '!'
	againRuntime, err := doc.IGVMRuntime()
	require.NoError(t, err)
	require.Equal(t, "manifest", string(againRuntime.Manifest))
	require.Equal(t, "{}", string(againRuntime.Bundle))

	empty := &Document{}
	_, err = empty.ConfigEndorsement()
	require.ErrorIs(t, err, collateral.ErrNotFound)
	_, err = empty.IGVMRuntime()
	require.ErrorIs(t, err, collateral.ErrNotFound)
}
