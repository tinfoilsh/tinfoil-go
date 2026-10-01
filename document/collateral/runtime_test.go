package collateral

import (
	"encoding/base64"
	"encoding/json/v2"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRuntimeReference(t *testing.T) {
	valid := RuntimeReference{Repo: RuntimeRepo, Tag: "v0.15.0-rc.1", Digest: strings.Repeat("ab", 32)}
	require.NoError(t, valid.Validate())
	for _, bad := range []RuntimeReference{
		{Repo: "other/runtime", Tag: valid.Tag, Digest: valid.Digest},
		{Repo: valid.Repo, Tag: "0.15.0", Digest: valid.Digest},
		{Repo: valid.Repo, Tag: "v0.15", Digest: valid.Digest},
		{Repo: valid.Repo, Tag: "v0.15.0+build", Digest: valid.Digest},
		{Repo: valid.Repo, Tag: valid.Tag, Digest: strings.ToUpper(valid.Digest)},
		{Repo: valid.Repo, Tag: valid.Tag, Digest: "ab"},
	} {
		require.Error(t, bad.Validate(), "%+v", bad)
	}
}

func TestIGVMRuntime(t *testing.T) {
	ref := RuntimeReference{Repo: RuntimeRepo, Tag: "v0.15.0", Digest: strings.Repeat("ab", 32)}
	manifest := []byte(`{"version":"v0.15.0"}`)
	data, err := json.Marshal(runtimeCollateral{RuntimeReference: ref, Manifest: base64.StdEncoding.EncodeToString(manifest), Bundle: []byte(`{}`)})
	require.NoError(t, err)
	entry := Entry{ID: RuntimeID, Role: RoleReferenceValues, Format: IGVMRuntimeV1Format, Data: data}
	set, err := Decode([]Entry{entry})
	require.NoError(t, err)
	got := set.Runtime
	require.NotNil(t, got)
	require.Equal(t, ref, got.RuntimeReference)
	require.Equal(t, manifest, got.Manifest)
	entries := []Entry{entry, entry}
	entries[1].ID = "other-runtime"
	_, err = Decode(entries)
	require.ErrorContains(t, err, "conflicting collateral")
}

func TestIGVMPlatform(t *testing.T) {
	entry := Entry{ID: PlatformID, Role: RoleReferenceValues, Format: SigstorePlatformV1Format,
		Data: []byte(`{"repo":"tinfoilsh/platform-endorsements","tag":"v1.0.0","digest":"ab","sigstore_bundle":{}}`)}
	set, err := Decode([]Entry{entry})
	require.NoError(t, err)
	platform, err := set.IGVMPlatform()
	require.NoError(t, err)
	require.Equal(t, "tinfoilsh/platform-endorsements", platform.Repo)
	platform.Bundle[0] = '!'
	again, err := set.IGVMPlatform()
	require.NoError(t, err)
	require.Equal(t, "{}", string(again.Bundle))

	for name, mutate := range map[string]func(*[]Entry){
		"missing":      func(entries *[]Entry) { *entries = nil },
		"wrong id":     func(entries *[]Entry) { (*entries)[0].ID = "other" },
		"wrong role":   func(entries *[]Entry) { (*entries)[0].Role = RoleEndorsement },
		"wrong format": func(entries *[]Entry) { (*entries)[0].Format = "https://tinfoil.sh/collateral/unknown/v1" },
		"multiple references": func(entries *[]Entry) {
			other := entry
			other.ID = "other"
			*entries = append(*entries, other)
		},
	} {
		t.Run(name, func(t *testing.T) {
			entries := []Entry{entry}
			mutate(&entries)
			set, err := Decode(entries)
			require.NoError(t, err)
			_, err = set.IGVMPlatform()
			if name == "missing" {
				require.ErrorIs(t, err, ErrNotFound)
			} else {
				require.ErrorContains(t, err, "conflicting platform collateral")
			}
		})
	}
}
