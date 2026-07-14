package tdx

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tdxabi "github.com/google/go-tdx-guest/abi"
	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
	tdxtestdata "github.com/google/go-tdx-guest/testing/testdata"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tinfoilsh/tinfoil-go/verifier/policy"
)

// Real production identifier (public by design in the endorsement artifact).
const inf7PPID = "3b064a0f58d5dd3688780aeb40e0b5d2"

func loadFixture(t *testing.T) *policy.Artifact {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "policy", "testdata", "platform-endorsements.json"))
	require.NoError(t, err)
	a, err := policy.Parse(data)
	require.NoError(t, err)
	return a
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

func TestOptions(t *testing.T) {
	a := loadFixture(t)
	_, p, err := a.PolicyFor(inf7PPID, policy.PlatformTDX)
	require.NoError(t, err)

	opts, err := options(p.TDX)
	require.NoError(t, err)
	assert.Equal(t, mustHex(t, "939a7233f79c4ca9940a0db3957f0607"), opts.HeaderOptions.QeVendorID)
	assert.Equal(t, make([]byte, 48), opts.TdQuoteBodyOptions.MrConfigID)
	assert.Equal(t, mustHex(t, "0000001000000000"), opts.TdQuoteBodyOptions.TdAttributes)
	require.NotEmpty(t, p.TDX.MRSeam)
	assert.Equal(t, mustHex(t, p.TDX.MRSeam), opts.TdQuoteBodyOptions.MrSeam)
}

// TestValidate exercises the single composed enforcement entry point against
// go-tdx-guest's production sample quote, with a policy derived from the
// quote itself, then flips each policy dimension that is NOT covered by the
// library options (tcbEvaluationDataNumber, the resolved platform
// measurement) to prove none of them can be silently skipped.
func TestValidate(t *testing.T) {
	parsed, err := tdxabi.QuoteToProto(tdxtestdata.RawQuote)
	require.NoError(t, err)
	proto, ok := parsed.(*tdxpb.QuoteV4)
	require.True(t, ok)
	body := proto.GetTdQuoteBody()

	var reportData [64]byte
	copy(reportData[:], body.GetReportData())
	code := CodeRegisters{
		RTMR1: body.GetRtmrs()[1],
		RTMR2: body.GetRtmrs()[2],
		RTMR3: body.GetRtmrs()[3],
	}
	quote := &Quote{quote: proto, TCBEvaluationDataNumber: 5}
	shape := &policy.Shape{CPUs: 8, MemoryMB: 65536, Disks: 4}

	minTCBEval := 5
	matching := &policy.TDXPolicy{
		QEVendorID:                     hex.EncodeToString(proto.GetHeader().GetQeVendorId()),
		MinimumQESVN:                   new(uint16),
		MinimumPCESVN:                  new(uint16),
		MinimumTEETCBSVN:               hex.EncodeToString(body.GetTeeTcbSvn()),
		MRSeam:                         hex.EncodeToString(body.GetMrSeam()),
		TDAttributes:                   hex.EncodeToString(body.GetTdAttributes()),
		XFAM:                           hex.EncodeToString(body.GetXfam()),
		MinimumTCBEvaluationDataNumber: &minTCBEval,
		PlatformMeasurements:           []string{"sample"},
	}
	a := &policy.Artifact{
		Measurements: map[string]policy.PlatformMeasurement{
			"sample": {
				MRTD:  hex.EncodeToString(body.GetMrTd()),
				RTMR0: hex.EncodeToString(body.GetRtmrs()[0]),
				Shape: shape,
			},
		},
	}

	assemble := func(a *policy.Artifact, p *policy.TDXPolicy) *Expectations {
		e, name, err := Assemble(a, p, shape, quote, code, reportData)
		require.NoError(t, err)
		assert.Equal(t, "sample", name)
		return e
	}

	require.NoError(t, assemble(a, matching).Validate(quote))

	badSeam := *matching
	badSeam.MRSeam = strings.Repeat("00", 48)
	assert.Error(t, assemble(a, &badSeam).Validate(quote))

	// A collateral floor above the observed number must reject.
	stale := *quote
	stale.TCBEvaluationDataNumber = 4
	assert.ErrorContains(t, assemble(a, matching).Validate(&stale), "below the policy minimum")

	// A quote whose MRTD/RTMR0 resolve no endorsed measurement fails at
	// assembly, before any validation runs.
	badMeasurements := &policy.Artifact{
		Measurements: map[string]policy.PlatformMeasurement{
			"sample": {MRTD: strings.Repeat("ff", 48), RTMR0: strings.Repeat("ff", 48), Shape: shape},
		},
	}
	_, _, err = Assemble(badMeasurements, matching, shape, quote, code, reportData)
	assert.ErrorContains(t, err, "do not match any allowed configuration")

	badOpts := *matching
	badOpts.TDAttributes = strings.Repeat("42", 8)
	assert.Error(t, assemble(a, &badOpts).Validate(quote))

	// A workload register differing from code provenance must reject.
	badCode := code
	badCode.RTMR1 = make([]byte, 48)
	e, _, err := Assemble(a, matching, shape, quote, badCode, reportData)
	require.NoError(t, err)
	assert.Error(t, e.Validate(quote))

	// A REPORT_DATA differing from the envelope's expectation must reject.
	var badReportData [64]byte
	e, _, err = Assemble(a, matching, shape, quote, code, badReportData)
	require.NoError(t, err)
	assert.Error(t, e.Validate(quote))
}
