package quote

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tinfoilsh/tinfoil-go/verify/document"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/policy"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/runtime"
	"github.com/tinfoilsh/tinfoil-go/verify/measurement"
)

func TestCodeMeasurementFollowsTheEvidenceFormat(t *testing.T) {
	launch, rtmr1 := measurement.Register{1}, measurement.Register{2}
	legacy := LegacyReferenceValues{
		SEVSNP: measurement.ExpectedSEVSNP{Launch: &launch},
		TDX:    measurement.ExpectedTDX{RTMR1: &rtmr1},
	}
	assert.Equal(t, legacy.SEVSNP, CodeMeasurement(legacy, document.SEVSNPReportV1Format))
	assert.Equal(t, legacy.TDX, CodeMeasurement(legacy, document.TDXQuoteV1Format))
	assert.Nil(t, CodeMeasurement(legacy, "unknown"))
	got := CodeMeasurement(legacy, document.SEVSNPReportV1Format).(measurement.ExpectedSEVSNP)
	*got.Launch = measurement.Register{9}
	assert.Equal(t, measurement.Register{1}, launch, "the result is a copy")

	zero := strings.Repeat("00", runtime.MeasurementSize)
	config := ConfigReferenceValues{Runtime: &runtime.Measurements{
		SNPLaunch: &runtime.SNPLaunch{Measurement: strings.Repeat("ab", runtime.MeasurementSize)},
		TDXLaunch: &runtime.TDXLaunch{MRTD: zero, RTMR0: zero, RTMR1: zero, RTMR2: zero, RTMR3: zero},
	}}
	sev := CodeMeasurement(config, document.SEVSNPReportV1Format).(measurement.ExpectedSEVSNP)
	assert.Equal(t, strings.Repeat("ab", runtime.MeasurementSize), sev.Launch.String())
	tdx := CodeMeasurement(config, document.TDXQuoteV1Format).(measurement.ExpectedTDX)
	assert.NotNil(t, tdx.RTMR3)
	assert.Nil(t, CodeMeasurement(ConfigReferenceValues{}, document.SEVSNPReportV1Format), "incomplete runtime endorsements fix nothing")
}

// resolvedRefs resolves to fixed values, so that assembly fails after them.
type resolvedRefs struct{ resolved *resolvedValues }

func (r resolvedRefs) resolve(*Authenticated, measurement.Expected) (*resolvedValues, error) {
	return r.resolved, nil
}
func (r resolvedRefs) code(string) (measurement.Expected, error) { return r.resolved.code, nil }

func TestAssembleReportsWhatItResolvedWhenItFails(t *testing.T) {
	launch := measurement.Register{1}
	expected := measurement.ExpectedSEVSNP{Launch: &launch}
	// The quote is TDX, so assembly fails after every register resolved.
	refs := resolvedRefs{&resolvedValues{policy: &policy.Policy{}, code: expected, expected: expected}}
	_, err := assemble(refs, nil, [64]byte{}, &Authenticated{platform: policy.PlatformTDX})
	var resolved *ResolvedError
	require.ErrorAs(t, err, &resolved)
	assert.Equal(t, measurement.SEVSNP{Launch: launch}, resolved.Expected)
	assert.ErrorContains(t, err, "expected an SEV-SNP measurement")
	assert.Equal(t, resolved.Err.Error(), err.Error(), "the message is the cause's")

	// A register that nothing fixes leaves the expectation unresolved.
	rtmr1 := measurement.Register{1}
	partial := measurement.ExpectedTDX{RTMR1: &rtmr1}
	refs = resolvedRefs{&resolvedValues{policy: &policy.Policy{}, code: partial, expected: partial}}
	_, err = assemble(refs, nil, [64]byte{}, &Authenticated{platform: policy.PlatformTDX})
	assert.ErrorContains(t, err, "nothing fixes the expected MRTD")
	assert.False(t, errors.As(err, &resolved))

	// So does a failure before resolution completes.
	_, err = assemble(LegacyReferenceValues{Endorsements: &policy.Artifact{}}, nil, [64]byte{}, &Authenticated{platform: policy.PlatformTDX})
	require.Error(t, err)
	assert.False(t, errors.As(err, &resolved))
}
