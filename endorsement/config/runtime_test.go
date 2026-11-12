package config_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	configendorsement "github.com/tinfoilsh/tinfoil-go/endorsement/config"
)

func TestRuntimeFromConfigReturnsErrorOnDecoderPanic(t *testing.T) {
	for _, config := range []string{
		"? [a]\n: 1\n<<: {b: 2}\ncvm-version: x\n",
		"<<: {b: 2}\n? [a]\n: 1\n",
		"? {a: 1}\n: 1\n<<: {b: 2}\n",
	} {
		_, err := configendorsement.RuntimeFromConfig([]byte(config))
		require.ErrorContains(t, err, "parsing config runtime pin", "config %q", config)
	}
}
