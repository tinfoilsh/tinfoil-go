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
