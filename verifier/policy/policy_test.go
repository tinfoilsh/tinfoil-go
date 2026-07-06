package policy

import (
	"encoding/hex"
	"os"
	"strings"
	"testing"

	tdxabi "github.com/google/go-tdx-guest/abi"
	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
	tdxtestdata "github.com/google/go-tdx-guest/testing/testdata"
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

	// "}" and "]" are the cases a dec.More() guard misses: More() peeks one
	// byte and returns false for closing brackets, silently accepting them.
	for _, trailing := range []string{"}", "]", "{}", "[1]", `"x"`, "{"} {
		_, err = ParseArtifact([]byte(string(data) + trailing))
		assert.ErrorContains(t, err, "trailing data", "trailing %q must be rejected", trailing)
	}
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

// SEVOptions must reject any non-Genoa product line.
func TestSEVOptionsRejectsNonGenoa(t *testing.T) {
	a := loadFixture(t)
	_, p, err := a.PolicyFor(box2TurinID, PlatformSEVSNP)
	require.NoError(t, err)

	_, err = p.SEVSNP.SEVOptions("Turin")
	assert.ErrorContains(t, err, "unsupported SEV product line")

	_, err = p.SEVSNP.SEVOptions("Milan")
	assert.ErrorContains(t, err, "unsupported SEV product line")
}

func TestTDXOptionsAndChecks(t *testing.T) {
	a := loadFixture(t)
	_, p, err := a.PolicyFor(inf7PPID, PlatformTDX)
	require.NoError(t, err)

	opts, err := p.TDX.tdxOptions()
	require.NoError(t, err)
	assert.Equal(t, mustHex(t, "939a7233f79c4ca9940a0db3957f0607"), opts.HeaderOptions.QeVendorID)
	assert.Equal(t, make([]byte, 48), opts.TdQuoteBodyOptions.MrConfigID)
	assert.Equal(t, mustHex(t, "0000001000000000"), opts.TdQuoteBodyOptions.TdAttributes)

	require.NotEmpty(t, p.TDX.AcceptedMRSeams)
	require.NoError(t, p.TDX.checkMRSeam(mustHex(t, p.TDX.AcceptedMRSeams[0])))
	assert.ErrorContains(t, p.TDX.checkMRSeam(make([]byte, 48)), "not in the policy's accepted set")

	ref := p.TDX.PlatformMeasurements[0]
	m := a.Measurements[ref]
	require.NoError(t, a.checkPlatformMeasurement(p.TDX, m.MRTD, m.RTMR0))
	assert.ErrorContains(t, a.checkPlatformMeasurement(p.TDX, strings.Repeat("ff", 48), m.RTMR0),
		"do not match any allowed configuration")

	require.NoError(t, p.TDX.checkTCBEvaluationDataNumber(p.TDX.MinimumTCBEvaluationDataNumber))
	assert.ErrorContains(t, p.TDX.checkTCBEvaluationDataNumber(p.TDX.MinimumTCBEvaluationDataNumber-1),
		"below the policy minimum")
}

// TestValidateTDXQuote exercises the single composed enforcement entry point
// against go-tdx-guest's production sample quote, with a policy derived from
// the quote itself, then flips each policy dimension that is NOT covered by
// the library options (MR_SEAM set, tcbEvaluationDataNumber, platform
// measurements) to prove none of them can be silently skipped.
func TestValidateTDXQuote(t *testing.T) {
	parsed, err := tdxabi.QuoteToProto(tdxtestdata.RawQuote)
	require.NoError(t, err)
	quote, ok := parsed.(*tdxpb.QuoteV4)
	require.True(t, ok)
	body := quote.GetTdQuoteBody()

	matching := &TDXPolicy{
		QEVendorID:                     hex.EncodeToString(quote.GetHeader().GetQeVendorId()),
		MinimumTEETCBSVN:               hex.EncodeToString(body.GetTeeTcbSvn()),
		AcceptedMRSeams:                []string{hex.EncodeToString(body.GetMrSeam())},
		TDAttributes:                   hex.EncodeToString(body.GetTdAttributes()),
		XFAM:                           hex.EncodeToString(body.GetXfam()),
		MinimumTCBEvaluationDataNumber: 5,
		PlatformMeasurements:           []string{"sample"},
	}
	a := &Artifact{
		Measurements: map[string]PlatformMeasurement{
			"sample": {
				MRTD:  hex.EncodeToString(body.GetMrTd()),
				RTMR0: hex.EncodeToString(body.GetRtmrs()[0]),
			},
		},
	}

	require.NoError(t, a.ValidateTDXQuote(matching, quote, 5))

	badSeam := *matching
	badSeam.AcceptedMRSeams = []string{strings.Repeat("00", 48)}
	assert.ErrorContains(t, a.ValidateTDXQuote(&badSeam, quote, 5), "not in the policy's accepted set")

	assert.ErrorContains(t, a.ValidateTDXQuote(matching, quote, 4), "below the policy minimum")

	badMeasurements := &Artifact{
		Measurements: map[string]PlatformMeasurement{
			"sample": {MRTD: strings.Repeat("ff", 48), RTMR0: strings.Repeat("ff", 48)},
		},
	}
	assert.ErrorContains(t, badMeasurements.ValidateTDXQuote(matching, quote, 5),
		"do not match any allowed configuration")

	badOpts := *matching
	badOpts.TDAttributes = strings.Repeat("42", 8)
	assert.Error(t, a.ValidateTDXQuote(&badOpts, quote, 5))
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
