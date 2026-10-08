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

	"github.com/tinfoilsh/tinfoil-go/verify/internal/policy"
	"github.com/tinfoilsh/tinfoil-go/verify/measurement"
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
	assert.Equal(t, mustHex(t, p.TDX.MinimumTEETCBSVN), opts.TdQuoteBodyOptions.MinimumTeeTcbSvn)
	assert.Equal(t, mustHex(t, p.TDX.XFAM), opts.TdQuoteBodyOptions.Xfam)
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
	rtmrs := body.GetRtmrs()
	code := [5]string{hex.EncodeToString(body.GetMrTd()), hex.EncodeToString(rtmrs[0]), hex.EncodeToString(rtmrs[1]), hex.EncodeToString(rtmrs[2]), hex.EncodeToString(rtmrs[3])}
	quote := &Quote{quote: proto, tcbEvaluationDataNumber: 5}

	minTCBEval := 5
	matching := &policy.TDXPolicy{
		QEVendorID:                     hex.EncodeToString(proto.GetHeader().GetQeVendorId()),
		MinimumTEETCBSVN:               hex.EncodeToString(body.GetTeeTcbSvn()),
		MRSeam:                         hex.EncodeToString(body.GetMrSeam()),
		TDAttributes:                   hex.EncodeToString(body.GetTdAttributes()),
		XFAM:                           hex.EncodeToString(body.GetXfam()),
		MinimumTCBEvaluationDataNumber: &minTCBEval,
		PlatformMeasurements:           []string{"sample"},
	}
	assemble := func(p *policy.TDXPolicy) *Expectations {
		e, err := Assemble(p, quote, code, reportData, [tdxabi.MrConfigIDSize]byte{})
		require.NoError(t, err)
		return e
	}

	require.NoError(t, assemble(matching).Validate(quote))

	for _, field := range []string{"mr_seam", "qe_vendor_id", "xfam", "td_attributes"} {
		t.Run(field, func(t *testing.T) {
			bad := *matching
			target := map[string]*string{
				"mr_seam":       &bad.MRSeam,
				"qe_vendor_id":  &bad.QEVendorID,
				"xfam":          &bad.XFAM,
				"td_attributes": &bad.TDAttributes,
			}[field]
			changed := mustHex(t, *target)
			changed[0] ^= 1
			*target = hex.EncodeToString(changed)
			e, err := Assemble(&bad, quote, code, reportData, [tdxabi.MrConfigIDSize]byte{})
			require.NoError(t, err)
			assert.ErrorContains(t, e.Validate(quote), strings.ToUpper(field))
		})
	}

	// A collateral floor above the observed number must reject.
	stale := *quote
	stale.tcbEvaluationDataNumber = 4
	assert.ErrorContains(t, assemble(matching).Validate(&stale), "below the policy minimum")

	// A platform register differing from the resolved reference value rejects.
	badCode := code
	badMRTD := mustHex(t, code[0])
	badMRTD[0] ^= 1
	badCode[0] = hex.EncodeToString(badMRTD)
	e, err := Assemble(matching, quote, badCode, reportData, [tdxabi.MrConfigIDSize]byte{})
	require.NoError(t, err)
	assert.Error(t, e.Validate(quote))

	// A workload register differing from code provenance must reject.
	badCode = code
	badRTMR1 := mustHex(t, code[2])
	badRTMR1[0] ^= 1
	badCode[2] = hex.EncodeToString(badRTMR1)
	e, err = Assemble(matching, quote, badCode, reportData, [tdxabi.MrConfigIDSize]byte{})
	require.NoError(t, err)
	assert.Error(t, e.Validate(quote))

	// A REPORT_DATA differing from the document's expectation must reject.
	badReportData := reportData
	badReportData[0] ^= 1
	e, err = Assemble(matching, quote, code, badReportData, [tdxabi.MrConfigIDSize]byte{})
	require.NoError(t, err)
	assert.Error(t, e.Validate(quote))

	e = assemble(matching)
	for i := range code {
		code[i] = strings.Repeat("ff", 48)
	}
	require.NoError(t, e.Validate(quote), "caller mutation must not change assembled expectations")
}

func TestPlatformMeasurementsUseAuthenticatedEvidence(t *testing.T) {
	parsed, err := tdxabi.QuoteToProto(tdxtestdata.RawQuote)
	require.NoError(t, err)
	raw := parsed.(*tdxpb.QuoteV4)
	q := &Quote{quote: raw, Measurement: &measurement.Measurement{Registers: []string{"substituted", "summary"}}}
	mrtd, rtmr0, err := q.PlatformMeasurements()
	require.NoError(t, err)
	require.Equal(t, hex.EncodeToString(raw.TdQuoteBody.MrTd), mrtd)
	require.Equal(t, hex.EncodeToString(raw.TdQuoteBody.Rtmrs[0]), rtmr0)
	for _, invalid := range []*Quote{nil, {}} {
		_, _, err := invalid.PlatformMeasurements()
		require.ErrorContains(t, err, "authenticated TDX quote is required")
	}
}
