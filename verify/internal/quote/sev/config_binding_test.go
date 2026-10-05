package sev

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tinfoilsh/tinfoil-go/verify/internal/policy"
)

func loadIGVMFixture(t *testing.T) *policy.Artifact {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "igvm", "platform-endorsements-igvm.json"))
	require.NoError(t, err)
	a, err := policy.Parse(data)
	require.NoError(t, err)
	return a
}

// An unresolved binding names no HOST_DATA. Assembling it would produce
// expectations that check the config not at all.
func TestOptionsRejectUnresolvedBinding(t *testing.T) {
	a := loadIGVMFixture(t)
	_, err := options(a.Policies["amd-turin-prod"].SEVSNP, ProductTurin)
	require.ErrorContains(t, err, "never resolved against a config")
}

// A resolved binding carries the config digest straight into HOST_DATA.
func TestResolvedBindingBecomesHostData(t *testing.T) {
	const digest = "301396c526d83a0ea03f823dd3a8621d9defc90e74d05e63f03325ae0fbc4ff0"
	resolved, err := loadIGVMFixture(t).Resolve(digest)
	require.NoError(t, err)
	opts, err := options(resolved.Policies["amd-turin-prod"].SEVSNP, ProductTurin)
	require.NoError(t, err)
	want, err := hex.DecodeString(digest)
	require.NoError(t, err)
	assert.Equal(t, want, opts.HostData)
}
