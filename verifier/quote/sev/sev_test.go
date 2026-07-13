package sev

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tinfoilsh/tinfoil-go/verifier/endorsement"
)

const (
	// Real production identifiers (public by design in the endorsement artifact).
	box3GenoaID = "cfdce31f5c40fc4e6eef803f6b5ed77e88b22603a91337bacab58446ab05fb8ef7bb5221611dced98dfa01d1eac114ca9a7952c262705977a36d81b0a53f856e"
	box2TurinID = "6bb1229b7692b7100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
)

func loadFixture(t *testing.T) *endorsement.Artifact {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "endorsement", "testdata", "platform-endorsements.json"))
	require.NoError(t, err)
	a, err := endorsement.Parse(data)
	require.NoError(t, err)
	return a
}

func TestOptionsGenoa(t *testing.T) {
	a := loadFixture(t)
	_, p, err := a.PolicyFor(box3GenoaID, endorsement.PlatformSEVSNP)
	require.NoError(t, err)

	opts, err := options(p.SEVSNP, ProductGenoa)
	require.NoError(t, err)
	assert.Equal(t, uint8(21), opts.MinimumBuild)
	assert.Equal(t, uint16(1<<8|55), opts.MinimumVersion)
	assert.Equal(t, uint8(7), opts.MinimumTCB.BlSpl)
	assert.Equal(t, uint8(14), opts.MinimumTCB.SnpSpl)
	assert.Equal(t, uint8(72), opts.MinimumTCB.UcodeSpl)
	assert.True(t, opts.GuestPolicy.SMT)
	assert.False(t, opts.GuestPolicy.Debug)
	require.NotNil(t, opts.PlatformInfo)
	assert.True(t, opts.PlatformInfo.TSMEEnabled)
}

func TestOptionsPinnedFields(t *testing.T) {
	hostData := strings.Repeat("ab", 32)
	imageID := strings.Repeat("cd", 16)
	p := endorsement.SEVSNPPolicy{
		MinimumAPIVersion: "1.55",
		HostData:          &hostData,
		ImageID:           &imageID,
		RequireAuthorKey:  true,
		RequireIDBlock:    true,
		GuestPolicy:       endorsement.GuestPolicy{SMT: true, PageSwapDisable: true},

		MinimumLaunchMitigationVector:  3,
		MinimumCurrentMitigationVector: 1,
	}
	opts, err := options(&p, ProductGenoa)
	require.NoError(t, err)
	assert.Len(t, opts.HostData, 32)
	assert.Len(t, opts.ImageID, 16)
	assert.Nil(t, opts.FamilyID)
	assert.True(t, opts.RequireAuthorKey)
	assert.True(t, opts.RequireIDBlock)
	assert.True(t, opts.GuestPolicy.PageSwapDisable)
	assert.Equal(t, uint64(3), opts.MinimumLaunchMitigationVector)
	assert.Equal(t, uint64(1), opts.MinimumCurrentMitigationVector)

	short := "abcd"
	p.HostData = &short
	_, err = options(&p, ProductGenoa)
	assert.ErrorContains(t, err, "host_data")
}

// options must reject any non-Genoa product line.
func TestOptionsRejectsNonGenoa(t *testing.T) {
	a := loadFixture(t)
	_, p, err := a.PolicyFor(box2TurinID, endorsement.PlatformSEVSNP)
	require.NoError(t, err)

	_, err = options(p.SEVSNP, "Turin")
	assert.ErrorContains(t, err, "unsupported SEV product line")

	_, err = options(p.SEVSNP, "Milan")
	assert.ErrorContains(t, err, "unsupported SEV product line")
}

func TestIdentity(t *testing.T) {
	raw, err := hex.DecodeString(box2TurinID)
	require.NoError(t, err)
	id, err := Identity(raw)
	require.NoError(t, err)
	assert.Equal(t, box2TurinID, id)

	_, err = Identity([]byte{1, 2, 3})
	assert.ErrorContains(t, err, "must be 64 bytes")
}
