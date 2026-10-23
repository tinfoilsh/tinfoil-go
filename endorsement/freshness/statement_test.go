package freshness

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPlatformReleaseIdentity(t *testing.T) {
	for _, tt := range []struct {
		tag   string
		valid bool
	}{
		{"platform-v1.2.3", true},
		{"platform-v1.2.3-rc.1", true},
		{"v1.2.3", false},
		{"platform-v1.2", false},
		{"platform-v1.2.3+build", false},
		{"platform-v01.2.3", false},
	} {
		t.Run(tt.tag, func(t *testing.T) {
			artifact := Artifact{Kind: KindPlatform, Repo: PlatformRepo, Tag: tt.tag, Name: PlatformName, Digest: strings.Repeat("a", 64)}
			_, err := NewStatement(artifact)
			if tt.valid {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
			artifact.Kind, artifact.Name = KindRuntime, RuntimeName(tt.tag)
			_, err = NewStatement(artifact)
			if tt.tag == "v1.2.3" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestRuntimeManifestIdentities(t *testing.T) {
	for _, tc := range []struct {
		tag, version string
		valid        bool
	}{
		{"v0.15.0", "v0.15.0", true},
		{"v0.15.0", "v0.15.0+gpu", true},
		{"v0.15.0-rc.1", "v0.15.0-rc.1+gpu", true},
		{"v0.15.0", "v0.15.0+mini", true},
		{"v0.15.0", "v0.15.0+containers.initrd-1", true},
		{"v0.15.0", "v0.15.0+GPU", true},
		{"v0.15.0", "v0.15.1+gpu", false},
		{"v0.15.0+gpu", "v0.15.0+gpu", false},
		{"v0.15.0", "v0.15.0+", false},
		{"v0.15.0", "v0.15.0+mini/other", false},
		{"v0.15.0", "v0.15+mini", false},
	} {
		t.Run(tc.tag+"/"+tc.version, func(t *testing.T) {
			artifact := Artifact{Kind: KindRuntime, Repo: RuntimeRepo, Tag: tc.tag, Name: RuntimeName(tc.version), Digest: strings.Repeat("ab", 32)}
			stmt, err := NewStatement(artifact)
			if !tc.valid {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, artifact, stmt.artifact())
			artifact.Name = "other-" + artifact.Name
			_, err = NewStatement(artifact)
			require.Error(t, err)
		})
	}
}
