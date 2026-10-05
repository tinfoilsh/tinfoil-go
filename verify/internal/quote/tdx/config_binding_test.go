package tdx

import (
	"encoding/hex"
	"strings"
	"testing"

	tdxabi "github.com/google/go-tdx-guest/abi"
	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
	tdxtestdata "github.com/google/go-tdx-guest/testing/testdata"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tinfoilsh/tinfoil-go/internal/errs"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/policy"
)

const configDigest = "301396c526d83a0ea03f823dd3a8621d9defc90e74d05e63f03325ae0fbc4ff0"

// A config-binding policy has no measurements map, no platform measurements,
// and no VM shape. All five registers come from the runtime manifest, so
// assembly must neither need a shape nor consult the measurements map.
func TestAssembleFromRuntimeRegisters(t *testing.T) {
	parsed, err := tdxabi.QuoteToProto(tdxtestdata.RawQuote)
	require.NoError(t, err)
	proto := parsed.(*tdxpb.QuoteV4)
	body := proto.GetTdQuoteBody()
	quote := &Quote{quote: proto, tcbEvaluationDataNumber: 5}

	var reportData [64]byte
	copy(reportData[:], body.GetReportData())
	rtmrs := body.GetRtmrs()
	registers := [5]string{
		hex.EncodeToString(body.GetMrTd()),
		hex.EncodeToString(rtmrs[0]), hex.EncodeToString(rtmrs[1]),
		hex.EncodeToString(rtmrs[2]), hex.EncodeToString(rtmrs[3]),
	}
	minTCBEval := 5
	bound := &policy.TDXPolicy{
		QEVendorID:                     hex.EncodeToString(proto.GetHeader().GetQeVendorId()),
		MinimumTEETCBSVN:               hex.EncodeToString(body.GetTeeTcbSvn()),
		MRSeam:                         hex.EncodeToString(body.GetMrSeam()),
		TDAttributes:                   hex.EncodeToString(body.GetTdAttributes()),
		XFAM:                           hex.EncodeToString(body.GetXfam()),
		MinimumTCBEvaluationDataNumber: &minTCBEval,
		MRConfigID:                     configDigest + strings.Repeat("0", 32),
	}

	e, name, err := Assemble(&policy.Artifact{}, bound, nil, quote, registers, reportData)
	require.NoError(t, err)
	assert.Empty(t, name, "no measurements-map entry was selected")
	assert.Equal(t, mustHex(t, bound.MRConfigID), e.opts.TdQuoteBodyOptions.MrConfigID)
	assert.Equal(t, mustHex(t, registers[0]), e.opts.TdQuoteBodyOptions.MrTd)

	// The sample quote's MRCONFIGID is zero, so it must be rejected against
	// the config digest and accepted against an explicitly zero register.
	require.Error(t, e.Validate(quote))
	zeroed := *bound
	zeroed.MRConfigID = strings.Repeat("00", 48)
	e, _, err = Assemble(&policy.Artifact{}, &zeroed, nil, quote, registers, reportData)
	require.NoError(t, err)
	require.NoError(t, e.Validate(quote))
}

// An unresolved binding must never be assembled: it names no expectation at
// all, and silently enforcing nothing is the failure mode that matters.
func TestAssembleRejectsUnresolvedBinding(t *testing.T) {
	a := loadIGVMFixture(t)
	_, _, err := Assemble(a, a.Policies["tdx-h200-prod"].TDX, nil, &Quote{quote: &tdxpb.QuoteV4{}}, [5]string{}, [64]byte{})
	require.ErrorContains(t, err, "never resolved against a config")
}

// A policy that enumerates platform measurements still requires a shape, and
// reports a missing one as an attestation failure: a document can pair an IGVM
// code artifact, which declares no shape, with such a policy.
func TestAssembleStillRequiresShapeForPlatformMeasurements(t *testing.T) {
	minTCBEval := 0
	p := &policy.TDXPolicy{
		QEVendorID: strings.Repeat("00", 16), MinimumTEETCBSVN: strings.Repeat("00", 16),
		MRSeam: strings.Repeat("00", 48), TDAttributes: strings.Repeat("00", 8),
		XFAM: strings.Repeat("00", 8), MinimumTCBEvaluationDataNumber: &minTCBEval,
		PlatformMeasurements: []string{"sample"},
	}
	_, _, err := Assemble(&policy.Artifact{}, p, nil, &Quote{quote: &tdxpb.QuoteV4{}}, [5]string{}, [64]byte{})
	require.ErrorContains(t, err, "declare no VM shape")
	var configErr *errs.ConfigurationError
	require.NotErrorAs(t, err, &configErr, "collateral can reach this, so it is not the caller's mistake")
}

// A policy naming no platform measurement expects reference values that fix
// MRTD and RTMR0. Without them nothing constrains either register, and
// assembly must say so rather than leave the hex decode to report it.
func TestAssembleRequiresRuntimeRegistersWithoutPlatformMeasurements(t *testing.T) {
	minTCBEval := 0
	p := &policy.TDXPolicy{
		QEVendorID: strings.Repeat("00", 16), MinimumTEETCBSVN: strings.Repeat("00", 16),
		MRSeam: strings.Repeat("00", 48), TDAttributes: strings.Repeat("00", 8),
		XFAM: strings.Repeat("00", 8), MinimumTCBEvaluationDataNumber: &minTCBEval,
		MRConfigID: configDigest + strings.Repeat("0", 32),
	}
	// The three registers a multiplatform code artifact supplies are not
	// enough: MRTD and RTMR0 would be whatever the quote happened to report.
	registers := [5]string{"", "", strings.Repeat("11", 48), strings.Repeat("22", 48), ""}
	_, _, err := Assemble(&policy.Artifact{}, p, nil, &Quote{quote: &tdxpb.QuoteV4{}}, registers, [64]byte{})
	require.ErrorContains(t, err, "no MRTD or RTMR0")
}
