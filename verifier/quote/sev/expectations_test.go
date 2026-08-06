package sev

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sevabi "github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tinfoilsh/tinfoil-go/verifier/policy"
)

const (
	// Real production identifiers (public by design in the endorsement artifact).
	box3GenoaID = "cfdce31f5c40fc4e6eef803f6b5ed77e88b22603a91337bacab58446ab05fb8ef7bb5221611dced98dfa01d1eac114ca9a7952c262705977a36d81b0a53f856e"
	box2TurinID = "6bb1229b7692b7100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
)

func loadFixture(t *testing.T) *policy.Artifact {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "policy", "testdata", "platform-endorsements.json"))
	require.NoError(t, err)
	a, err := policy.Parse(data)
	require.NoError(t, err)
	return a
}

func TestOptionsGenoa(t *testing.T) {
	a := loadFixture(t)
	_, p, err := a.PolicyFor(box3GenoaID, policy.PlatformSEVSNP)
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
	p := policy.SEVSNPPolicy{
		MinimumBuild:      ptr(uint8(21)),
		MinimumAPIVersion: "1.55",
		MinimumABIVersion: "0.31",
		MinimumGuestSVN:   ptr(uint32(0)),
		MinimumTCB:        testTCB(),
		MinimumLaunchTCB:  testTCB(),
		VMPL:              ptr(0),
		HostData:          strings.Repeat("ab", 32),
		ImageID:           strings.Repeat("cd", 16),
		FamilyID:          strings.Repeat("ef", 16),
		GuestPolicy:       policy.GuestPolicy{SMT: true, PageSwapDisable: true},

		MinimumLaunchMitigationVector:  ptr(uint64(3)),
		MinimumCurrentMitigationVector: ptr(uint64(1)),
	}
	opts, err := options(&p, ProductGenoa)
	require.NoError(t, err)
	assert.Len(t, opts.HostData, 32)
	assert.Len(t, opts.ImageID, 16)
	assert.Len(t, opts.FamilyID, 16)
	assert.True(t, opts.GuestPolicy.PageSwapDisable)
	assert.Equal(t, uint64(3), opts.MinimumLaunchMitigationVector)
	assert.Equal(t, uint64(1), opts.MinimumCurrentMitigationVector)

	// The pinned fields are required: absent or malformed values reject.
	p.HostData = "abcd"
	_, err = options(&p, ProductGenoa)
	assert.ErrorContains(t, err, "host_data")
	p.HostData = ""
	_, err = options(&p, ProductGenoa)
	assert.ErrorContains(t, err, "host_data")

	// ID-block trust material is not modeled: requiring it must reject.
	p.HostData = strings.Repeat("ab", 32)
	p.RequireIDBlock = true
	_, err = options(&p, ProductGenoa)
	assert.ErrorContains(t, err, "not supported")
}

// options must reject any non-Genoa product line.
func TestOptionsRejectsNonGenoa(t *testing.T) {
	a := loadFixture(t)
	_, p, err := a.PolicyFor(box2TurinID, policy.PlatformSEVSNP)
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

func TestCheckSignerRejectsMaskedChipID(t *testing.T) {
	report := &sevsnp.Report{
		SignerInfo: sevabi.ComposeSignerInfo(sevabi.SignerInfo{
			SigningKey:  sevabi.VcekReportSigner,
			MaskChipKey: true,
		}),
	}
	err := new(Expectations).checkSigner(report)
	assert.ErrorContains(t, err, "masks CHIP_ID")
}

func ptr[T any](v T) *T { return &v }

func testTCB() policy.TCB {
	return policy.TCB{
		BlSpl:    ptr(uint8(0)),
		TeeSpl:   ptr(uint8(0)),
		SnpSpl:   ptr(uint8(0)),
		UcodeSpl: ptr(uint8(0)),
	}
}
