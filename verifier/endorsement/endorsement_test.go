package endorsement

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// Real production identifiers (public by design in the endorsement artifact).
	box2TurinID = "6bb1229b7692b7100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	inf7PPID    = "3b064a0f58d5dd3688780aeb40e0b5d2"
)

func loadFixture(t *testing.T) *Artifact {
	t.Helper()
	data, err := os.ReadFile("testdata/platform-endorsements.json")
	require.NoError(t, err)
	a, err := Parse(data)
	require.NoError(t, err)
	return a
}

func TestParseArtifactFixture(t *testing.T) {
	a := loadFixture(t)
	assert.Len(t, a.Machines, 12)
	assert.Len(t, a.Policies, 6)
	assert.Len(t, a.Measurements, 16)
}

func TestParseArtifactFailClosed(t *testing.T) {
	data, err := os.ReadFile("testdata/platform-endorsements.json")
	require.NoError(t, err)

	unknownField := strings.Replace(string(data), `"machines"`, `"surprise": {}, "machines"`, 1)
	_, err = Parse([]byte(unknownField))
	assert.ErrorContains(t, err, "surprise")

	wrongFormat := strings.Replace(string(data), "platform-endorsements/v1", "platform-endorsements/v9", 1)
	_, err = Parse([]byte(wrongFormat))
	assert.ErrorContains(t, err, "unsupported artifact format")

	danglingRef := strings.Replace(string(data), `"amd-genoa-prod"`, `"no-such-policy"`, 1)
	_, err = Parse([]byte(danglingRef))
	assert.ErrorContains(t, err, "unknown policy")

	// A negative minimum would make checkTCBEvaluationDataNumber pass for
	// any collateral, silently disabling the freshness floor.
	negativeMin := strings.Replace(string(data),
		`"minimum_tcb_evaluation_data_number": 19`,
		`"minimum_tcb_evaluation_data_number": -1`, 1)
	require.NotEqual(t, string(data), negativeMin)
	_, err = Parse([]byte(negativeMin))
	assert.ErrorContains(t, err, "must not be negative")

	// "}" and "]" are the cases a dec.More() guard misses: More() peeks one
	// byte and returns false for closing brackets, silently accepting them.
	for _, trailing := range []string{"}", "]", "{}", "[1]", `"x"`, "{"} {
		_, err = Parse([]byte(string(data) + trailing))
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

func TestResolvePlatformMeasurementShapeFilter(t *testing.T) {
	gpus := func(n int) *int { return &n }
	shapeA := Shape{CPUs: 8, MemoryMB: 65536, GPUs: gpus(1), Disks: 4}
	shapeB := Shape{CPUs: 32, MemoryMB: 524288, GPUs: gpus(2), Disks: 5}
	a := &Artifact{
		Measurements: map[string]PlatformMeasurement{
			"one-disk": {MRTD: "aa", RTMR0: "bb", Shape: &shapeA},
			"two-disk": {MRTD: "cc", RTMR0: "dd", Shape: &shapeB},
			"no-gpus":  {MRTD: "11", RTMR0: "22", Shape: &Shape{CPUs: 8, MemoryMB: 65536, Disks: 4}},
			"legacy":   {MRTD: "ee", RTMR0: "ff"},
		},
	}
	p := &TDXPolicy{PlatformMeasurements: []string{"one-disk", "two-disk", "no-gpus", "legacy"}}

	// Unfiltered lookup resolves any allowed entry.
	name, _, err := a.ResolvePlatformMeasurement(p, nil, "ee", "ff")
	require.NoError(t, err)
	assert.Equal(t, "legacy", name)

	// The shape filter restricts candidates before the measurement lookup.
	name, m, err := a.ResolvePlatformMeasurement(p, &shapeA, "aa", "bb")
	require.NoError(t, err)
	assert.Equal(t, "one-disk", name)
	assert.Equal(t, &shapeA, m.Shape)

	// A slug without a GPU count satisfies any required GPU count.
	name, _, err = a.ResolvePlatformMeasurement(p, &shapeA, "11", "22")
	require.NoError(t, err)
	assert.Equal(t, "no-gpus", name)

	// A quote from an endorsed but differently-shaped VM must not resolve.
	_, _, err = a.ResolvePlatformMeasurement(p, &shapeA, "cc", "dd")
	assert.ErrorContains(t, err, "do not match any allowed configuration")

	// Entries without shape metadata are never candidates under a filter.
	_, _, err = a.ResolvePlatformMeasurement(p, &shapeA, "ee", "ff")
	assert.ErrorContains(t, err, "do not match any allowed configuration")

	// A shape no endorsed entry was measured for reports the shape itself.
	_, _, err = a.ResolvePlatformMeasurement(p, &Shape{CPUs: 1}, "aa", "bb")
	assert.ErrorContains(t, err, "required VM shape")
}
