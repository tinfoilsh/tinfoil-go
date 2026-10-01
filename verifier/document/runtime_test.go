package document

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
	entry := CollateralEntry{ID: RuntimeCollateralID, Role: RoleReferenceValues, Format: CollateralIGVMRuntimeV1Format, Data: data}
	doc := &Document{collateral: []CollateralEntry{entry}}
	got, err := doc.IGVMRuntime()
	require.NoError(t, err)
	require.Equal(t, ref, got.RuntimeReference)
	require.Equal(t, manifest, got.Manifest)
	doc.collateral = append(doc.collateral, entry)
	doc.collateral[1].ID = "other-runtime"
	_, err = doc.IGVMRuntime()
	require.ErrorContains(t, err, "conflicting collateral")
}
