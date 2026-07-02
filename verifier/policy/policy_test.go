package policy

import (
	"encoding/binary"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// Real production identifiers (public by design in the endorsement artifact).
	box3GenoaID = "cfdce31f5c40fc4e6eef803f6b5ed77e88b22603a91337bacab58446ab05fb8ef7bb5221611dced98dfa01d1eac114ca9a7952c262705977a36d81b0a53f856e"
	box2TurinID = "6bb1229b7692b7100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	inf7PPID    = "3b064a0f58d5dd3688780aeb40e0b5d2"
)

func loadFixture(t *testing.T) *Artifact {
	t.Helper()
	data, err := os.ReadFile("testdata/platform-endorsements.json")
	require.NoError(t, err)
	a, err := ParseArtifact(data)
	require.NoError(t, err)
	return a
}

func TestParseArtifactFixture(t *testing.T) {
	a := loadFixture(t)
	assert.Len(t, a.Machines, 12)
	assert.Len(t, a.Policies, 5)
	assert.Len(t, a.Measurements, 16)
}

func TestParseArtifactFailClosed(t *testing.T) {
	data, err := os.ReadFile("testdata/platform-endorsements.json")
	require.NoError(t, err)

	unknownField := strings.Replace(string(data), `"machines"`, `"surprise": {}, "machines"`, 1)
	_, err = ParseArtifact([]byte(unknownField))
	assert.ErrorContains(t, err, "surprise")

	wrongFormat := strings.Replace(string(data), "platform-endorsements/v1", "platform-endorsements/v9", 1)
	_, err = ParseArtifact([]byte(wrongFormat))
	assert.ErrorContains(t, err, "unsupported artifact format")

	danglingRef := strings.Replace(string(data), `"amd-genoa-prod"`, `"no-such-policy"`, 1)
	_, err = ParseArtifact([]byte(danglingRef))
	assert.ErrorContains(t, err, "unknown policy")
}

func TestPolicyLookup(t *testing.T) {
	a := loadFixture(t)

	name, p, err := a.PolicyFor(box2TurinID, PlatformSEVSNP)
	require.NoError(t, err)
	assert.Equal(t, "amd-turin-prod", name)
	require.NotNil(t, p.SEVSNP)

	name, p, err = a.PolicyFor(inf7PPID, PlatformTDX)
	require.NoError(t, err)
	assert.Equal(t, "tdx-h200-prod", name)
	require.NotNil(t, p.TDX)

	// Platform mismatch: TDX identifier presented as SEV evidence.
	_, _, err = a.PolicyFor(inf7PPID, PlatformSEVSNP)
	assert.ErrorContains(t, err, "is for platform")

	// Unknown machine: unconditional rejection.
	_, _, err = a.PolicyFor(strings.Repeat("ab", 64), PlatformSEVSNP)
	assert.ErrorContains(t, err, "not endorsed")
}

func TestSEVOptionsGenoa(t *testing.T) {
	a := loadFixture(t)
	_, p, err := a.PolicyFor(box3GenoaID, PlatformSEVSNP)
	require.NoError(t, err)

	opts, err := p.SEVSNP.SEVOptions(ProductGenoa)
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

func TestSEVOptionsTurin(t *testing.T) {
	a := loadFixture(t)
	_, p, err := a.PolicyFor(box2TurinID, PlatformSEVSNP)
	require.NoError(t, err)

	opts, err := p.SEVSNP.SEVOptions(ProductTurin)
	require.NoError(t, err)
	// Turin TCB floors are enforced via CheckTurinTCB, not library options.
	assert.Zero(t, opts.MinimumTCB.UcodeSpl)

	// A Turin policy fed to the Genoa translation must fail (fmc_spl set).
	_, err = p.SEVSNP.SEVOptions(ProductGenoa)
	assert.ErrorContains(t, err, "fmc_spl")

	_, err = p.SEVSNP.SEVOptions("Milan")
	assert.ErrorContains(t, err, "unsupported SEV product line")
}

func TestCheckTurinTCB(t *testing.T) {
	a := loadFixture(t)
	_, p, err := a.PolicyFor(box2TurinID, PlatformSEVSNP)
	require.NoError(t, err)

	// box2's real reported TCB bytes as they appear in the report (little endian).
	raw := binary.LittleEndian.Uint64(mustHex(t, "0101010400000052"))
	decomposed := DecomposeTurinTCB(raw)
	assert.Equal(t, uint8(1), decomposed.FmcSpl)
	assert.Equal(t, uint8(1), decomposed.BlSpl)
	assert.Equal(t, uint8(1), decomposed.TeeSpl)
	assert.Equal(t, uint8(4), decomposed.SnpSpl)
	assert.Equal(t, uint8(82), decomposed.UcodeSpl)

	require.NoError(t, p.SEVSNP.CheckTurinTCB("reported_tcb", raw, p.SEVSNP.MinimumTCB))

	older := binary.LittleEndian.Uint64(mustHex(t, "0101010400000051")) // ucode 81 < floor 82
	assert.ErrorContains(t, p.SEVSNP.CheckTurinTCB("reported_tcb", older, p.SEVSNP.MinimumTCB), "below policy floor")
}

func TestTDXOptionsAndChecks(t *testing.T) {
	a := loadFixture(t)
	_, p, err := a.PolicyFor(inf7PPID, PlatformTDX)
	require.NoError(t, err)

	opts, err := p.TDX.TDXOptions()
	require.NoError(t, err)
	assert.Equal(t, mustHex(t, "939a7233f79c4ca9940a0db3957f0607"), opts.HeaderOptions.QeVendorID)
	assert.Equal(t, make([]byte, 48), opts.TdQuoteBodyOptions.MrConfigID)
	assert.Equal(t, mustHex(t, "0000001000000000"), opts.TdQuoteBodyOptions.TdAttributes)

	require.NotEmpty(t, p.TDX.AcceptedMRSeams)
	require.NoError(t, p.TDX.CheckMRSeam(mustHex(t, p.TDX.AcceptedMRSeams[0])))
	assert.ErrorContains(t, p.TDX.CheckMRSeam(make([]byte, 48)), "not in the policy's accepted set")

	ref := p.TDX.PlatformMeasurements[0]
	m := a.Measurements[ref]
	require.NoError(t, a.CheckPlatformMeasurement(p.TDX, m.MRTD, m.RTMR0))
	assert.ErrorContains(t, a.CheckPlatformMeasurement(p.TDX, strings.Repeat("ff", 48), m.RTMR0),
		"do not match any allowed configuration")
}

func TestSEVIdentity(t *testing.T) {
	id, err := SEVIdentity(mustHex(t, box2TurinID))
	require.NoError(t, err)
	assert.Equal(t, box2TurinID, id)

	_, err = SEVIdentity([]byte{1, 2, 3})
	assert.ErrorContains(t, err, "must be 64 bytes")
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}
