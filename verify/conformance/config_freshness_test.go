//go:build tinfoil_conformance

package conformance

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/document/collateral"
)

func TestConfigBoundRequiresIndependentFreshness(t *testing.T) {
	data, err := os.ReadFile("testdata/igvm-snp.json")
	require.NoError(t, err)
	var f fixture
	require.NoError(t, json.Unmarshal(data, &f))
	accepted, code := Run(f.Stage, f.Input)
	require.Equal(t, ExitAccepted, code)
	require.True(t, accepted.Accepted)
	require.Equal(t, f.Expected.Config.FreshnessExpiresAtUnix, accepted.Outputs.Config.FreshnessExpiresAtUnix)

	for name, change := range map[string]func(*Input){
		"missing runtime approval": func(in *Input) {
			changeFreshnessEntry(t, in, collateral.FreshnessIDRuntime, true, false)
		},
		"missing platform approval": func(in *Input) {
			changeFreshnessEntry(t, in, collateral.FreshnessIDPlatform, true, false)
		},
		"legacy platform format": func(in *Input) {
			changeFreshnessEntry(t, in, collateral.FreshnessIDPlatform, false, true)
		},
		"legacy runtime format": func(in *Input) {
			changeFreshnessEntry(t, in, collateral.FreshnessIDRuntime, false, true)
		},
		"swapped approval bundles": func(in *Input) {
			editFreshnessEntries(t, in, func(entries []collateral.Entry) []collateral.Entry {
				platform, runtime := -1, -1
				for i, entry := range entries {
					switch entry.ID {
					case collateral.FreshnessIDPlatform:
						platform = i
					case collateral.FreshnessIDRuntime:
						runtime = i
					}
				}
				require.NotEqual(t, -1, platform)
				require.NotEqual(t, -1, runtime)
				entries[platform].Data, entries[runtime].Data = entries[runtime].Data, entries[platform].Data
				return entries
			})
		},
		"public defaults reject private artifact signatures": func(in *Input) {
			in.FreshnessSigningKeyPEM = ""
		},
		"public defaults reject private config signatures": func(in *Input) {
			config := *in.Config
			config.PublicKeyPEM = ""
			in.Config = &config
		},
		"config authority cannot approve artifacts": func(in *Input) {
			in.FreshnessSigningKeyPEM = in.Config.PublicKeyPEM
		},
		"runtime expires before config and platform": func(in *Input) {
			in.VerificationTimeUnix = f.Expected.Config.FreshnessExpiresAtUnix + 1
		},
	} {
		t.Run(name, func(t *testing.T) {
			in := f.Input
			change(&in)
			out, code := Run(f.Stage, in)
			require.Equal(t, ExitRejected, code)
			require.False(t, out.Accepted)
		})
	}
}

func changeFreshnessEntry(t *testing.T, in *Input, id string, remove, legacyFormat bool) {
	t.Helper()
	editFreshnessEntries(t, in, func(entries []collateral.Entry) []collateral.Entry {
		found := false
		for i := range entries {
			if entries[i].ID != id {
				continue
			}
			found = true
			if remove {
				entries = append(entries[:i], entries[i+1:]...)
			} else if legacyFormat {
				entries[i].Format = collateral.SigstoreFreshnessV1Format
			}
			break
		}
		require.True(t, found)
		return entries
	})
}

func editFreshnessEntries(t *testing.T, in *Input, edit func([]collateral.Entry) []collateral.Entry) {
	t.Helper()
	encoded, err := base64.StdEncoding.DecodeString(in.DocumentB64)
	require.NoError(t, err)
	var doc map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(encoded, &doc))
	var entries []collateral.Entry
	require.NoError(t, json.Unmarshal(doc["collateral"], &entries))
	doc["collateral"], err = json.Marshal(edit(entries))
	require.NoError(t, err)
	encoded, err = json.Marshal(doc)
	require.NoError(t, err)
	in.DocumentB64 = base64.StdEncoding.EncodeToString(encoded)
}
