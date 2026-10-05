package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The real published IGVM artifact: every policy binds its config, and no
// policy names a platform measurement.
func loadIGVMFixture(t *testing.T) *Artifact {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "igvm", "platform-endorsements-igvm.json"))
	require.NoError(t, err)
	a, err := Parse(data)
	require.NoError(t, err)
	return a
}

const testDigest = "301396c526d83a0ea03f823dd3a8621d9defc90e74d05e63f03325ae0fbc4ff0"

func TestResolveFillsBothPlatforms(t *testing.T) {
	a := loadIGVMFixture(t)
	resolved, err := a.Resolve(testDigest)
	require.NoError(t, err)

	for name, p := range resolved.Policies {
		switch p.Platform {
		case PlatformSEVSNP:
			assert.Equal(t, testDigest, p.SEVSNP.HostData, name)
			assert.Empty(t, p.SEVSNP.ConfigBinding, name)
		case PlatformTDX:
			assert.Equal(t, testDigest+strings.Repeat("0", 32), p.TDX.MRConfigID, name)
			assert.Empty(t, p.TDX.ConfigBinding, name)
		}
	}
}

// Resolution must not reach back into the artifact it copied: a verifier
// holding one authenticated artifact may appraise several documents.
func TestResolveDoesNotMutateSource(t *testing.T) {
	a := loadIGVMFixture(t)
	_, err := a.Resolve(testDigest)
	require.NoError(t, err)
	for name, p := range a.Policies {
		if p.SEVSNP != nil {
			assert.Equal(t, ConfigBindingSHA256, p.SEVSNP.ConfigBinding, name)
			assert.Empty(t, p.SEVSNP.HostData, name)
		}
		if p.TDX != nil {
			assert.Equal(t, ConfigBindingSHA256, p.TDX.ConfigBinding, name)
			assert.Empty(t, p.TDX.MRConfigID, name)
		}
	}
}

// A legacy artifact has nothing to resolve, and resolving it anyway would
// leave its launch registers unchecked. Refusing is what keeps the two
// artifacts from being used interchangeably.
func TestResolveRejectsUnboundPolicies(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "platform-endorsements.json"))
	require.NoError(t, err)
	legacy, err := Parse(data)
	require.NoError(t, err)
	_, err = legacy.Resolve(testDigest)
	require.ErrorContains(t, err, "declares no config_binding")
}

func TestResolveRejectsBadDigest(t *testing.T) {
	a := loadIGVMFixture(t)
	for _, digest := range []string{"", "zz", strings.ToUpper(testDigest), testDigest + "00"} {
		_, err := a.Resolve(digest)
		require.Error(t, err, digest)
	}
}

// Parsing must reject a policy that declares both a fixed value and a
// binding: one of the two would silently win.
func TestValidateRejectsBindingWithFixedValue(t *testing.T) {
	a := loadIGVMFixture(t)
	p := a.Policies["amd-turin-prod"]
	snp := *p.SEVSNP
	snp.HostData = testDigest
	require.ErrorContains(t, snp.Validate(), "mutually exclusive")

	tdx := *a.Policies["tdx-h200-prod"].TDX
	tdx.MRConfigID = testDigest + strings.Repeat("0", 32)
	require.ErrorContains(t, tdx.Validate(), "excludes")
}

// A policy carrying no block at all binds nothing, and must be refused rather
// than skipped.
func TestResolveRejectsPolicyWithNoBlock(t *testing.T) {
	a := loadIGVMFixture(t)
	a.Policies["amd-turin-prod"] = Policy{Platform: PlatformSEVSNP}
	_, err := a.Resolve(testDigest)
	require.ErrorContains(t, err, "declares no config_binding")
}

// An unknown binding must not parse at all, not merely fail to resolve.
func TestValidateRejectsUnknownBindingAtParse(t *testing.T) {
	a := loadIGVMFixture(t)
	snp := *a.Policies["amd-turin-prod"].SEVSNP
	snp.ConfigBinding = "blake3"
	require.ErrorContains(t, snp.Validate(), "unsupported config_binding")

	tdx := *a.Policies["tdx-h200-prod"].TDX
	tdx.ConfigBinding = "blake3"
	require.ErrorContains(t, tdx.Validate(), "unsupported config_binding")
}
