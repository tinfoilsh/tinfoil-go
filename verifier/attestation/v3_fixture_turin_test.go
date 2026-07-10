package attestation

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVerifyV3LiveFixtureTurin checks the fail-closed behavior for AMD Turin
// (family 1Ah) hardware, which the verifier does not support yet: the
// envelope of a real Turin-served document verifies, but CPU evidence
// verification must reject rather than partially apply. Skips when the
// fixture is absent.
func TestVerifyV3LiveFixtureTurin(t *testing.T) {
	doc, reportData, _ := loadLiveFixture(t, "box2-turin-v3")
	require.Equal(t, SEVSNPReportV1Format, doc.CPUEvidence.Format)

	// Turin quotes must fail verification, never partially verify.
	_, err := VerifyCPUEvidenceV3(doc, reportData, loadEndorsementArtifact(t))
	assert.Error(t, err)
}
