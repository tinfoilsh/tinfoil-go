package policy

import (
	"encoding/json/v2"
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

func TestParsePlatformMeasurementValidation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*PlatformMeasurement)
		want   string
	}{
		{"optional GPUs", func(m *PlatformMeasurement) {}, ""},
		{"zero GPUs", func(m *PlatformMeasurement) { m.Shape.GPUs = new(0) }, ""},
		{"positive GPUs", func(m *PlatformMeasurement) { m.Shape.GPUs = new(1) }, ""},
		{"missing shape", func(m *PlatformMeasurement) { m.Shape = nil }, "shape is required"},
		{"zero CPUs", func(m *PlatformMeasurement) { m.Shape.CPUs = 0 }, "must be positive"},
		{"negative CPUs", func(m *PlatformMeasurement) { m.Shape.CPUs = -1 }, "must be positive"},
		{"zero memory", func(m *PlatformMeasurement) { m.Shape.MemoryMB = 0 }, "must be positive"},
		{"negative memory", func(m *PlatformMeasurement) { m.Shape.MemoryMB = -1 }, "must be positive"},
		{"zero disks", func(m *PlatformMeasurement) { m.Shape.Disks = 0 }, "must be positive"},
		{"negative disks", func(m *PlatformMeasurement) { m.Shape.Disks = -1 }, "must be positive"},
		{"negative GPUs", func(m *PlatformMeasurement) { m.Shape.GPUs = new(-1) }, "gpus must be non-negative"},
		{"missing MRTD", func(m *PlatformMeasurement) { m.MRTD = "" }, "mrtd"},
		{"short MRTD", func(m *PlatformMeasurement) { m.MRTD = strings.Repeat("ab", 47) }, "mrtd"},
		{"oversized MRTD", func(m *PlatformMeasurement) { m.MRTD = strings.Repeat("AB", 1<<19) }, "mrtd must be 96 hex chars"},
		{"nonhex MRTD", func(m *PlatformMeasurement) { m.MRTD = strings.Repeat("z", 96) }, "mrtd"},
		{"uppercase MRTD", func(m *PlatformMeasurement) { m.MRTD = strings.ToUpper(m.MRTD) }, "mrtd"},
		{"missing RTMR0", func(m *PlatformMeasurement) { m.RTMR0 = "" }, "rtmr0"},
		{"short RTMR0", func(m *PlatformMeasurement) { m.RTMR0 = strings.Repeat("ab", 47) }, "rtmr0"},
		{"oversized RTMR0", func(m *PlatformMeasurement) { m.RTMR0 = strings.Repeat("AB", 1<<19) }, "rtmr0 must be 96 hex chars"},
		{"nonhex RTMR0", func(m *PlatformMeasurement) { m.RTMR0 = strings.Repeat("z", 96) }, "rtmr0"},
		{"uppercase RTMR0", func(m *PlatformMeasurement) { m.RTMR0 = strings.ToUpper(m.RTMR0) }, "rtmr0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := PlatformMeasurement{MRTD: strings.Repeat("ab", 48), RTMR0: strings.Repeat("cd", 48),
				Shape: &Shape{CPUs: 1, MemoryMB: 1, Disks: 1}}
			tt.mutate(&m)
			// Even an entry unused by any policy must be well formed.
			data, err := json.Marshal(Artifact{Format: ArtifactFormat, Measurements: map[string]PlatformMeasurement{"test": m}})
			require.NoError(t, err)
			_, err = Parse(data)
			if tt.want == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tt.want)
			}
		})
	}
}

func TestParseArtifactFailClosed(t *testing.T) {
	data, err := os.ReadFile("testdata/platform-endorsements.json")
	require.NoError(t, err)

	wrongFormat := strings.Replace(string(data), "platform-endorsements/v1", "platform-endorsements/v9", 1)
	_, err = Parse([]byte(wrongFormat))
	assert.ErrorContains(t, err, "unsupported artifact format")

	danglingRef := strings.Replace(string(data), `"amd-genoa-prod"`, `"no-such-policy"`, 1)
	_, err = Parse([]byte(danglingRef))
	assert.ErrorContains(t, err, "unknown policy")

	// A negative minimum would let any observed collateral satisfy the floor.
	negativeMin := strings.Replace(string(data),
		`"minimum_tcb_evaluation_data_number": 19`,
		`"minimum_tcb_evaluation_data_number": -1`, 1)
	require.NotEqual(t, string(data), negativeMin)
	_, err = Parse([]byte(negativeMin))
	assert.ErrorContains(t, err, "must not be negative")
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

	// The required shape is not optional.
	_, _, err := a.ResolvePlatformMeasurement(p, nil, "ee", "ff")
	assert.ErrorContains(t, err, "required VM shape is missing")

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
