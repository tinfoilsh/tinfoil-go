package verify

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/tinfoilsh/tinfoil-go/internal/sdkinfo"
	"github.com/tinfoilsh/tinfoil-go/verify/document"
	"github.com/tinfoilsh/tinfoil-go/verify/document/collateral"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/runtime"
	"github.com/tinfoilsh/tinfoil-go/verify/measurement"
)

// requireReport asserts that err is a VerificationError from layer whose
// report fails that layer with the error's text, after which no step ran,
// and returns the report.
func requireReport(t *testing.T, err error, layer Layer, at time.Time) *VerificationReport {
	t.Helper()
	var rejected *VerificationError
	require.ErrorAs(t, err, &rejected)
	require.Equal(t, layer, rejected.Layer)
	report := rejected.Report
	require.NotNil(t, report)
	require.Nil(t, report.VerifiedFacts, "a rejected document proves nothing")
	require.NotNil(t, report.PartialFacts)
	require.Equal(t, layers, stepLayers(report.Steps))
	failedAt := slices.Index(layers, layer)
	for i, step := range report.Steps {
		switch {
		case i < failedAt:
			require.Contains(t, []StepStatus{StepPassed, StepSkipped}, step.Status, step.Layer)
		case i == failedAt:
			require.Equal(t, StepFailed, step.Status)
			require.Equal(t, rejected.Err.Error(), step.Message)
		default:
			require.Equal(t, StepNotRun, step.Status, step.Layer)
			require.Empty(t, step.Message)
		}
	}
	failed, ok := report.Failed()
	require.True(t, ok)
	require.Equal(t, layer, failed.Layer)
	require.Equal(t, SoftwareIdentity{Name: sdkinfo.Name, Version: sdkinfo.Version()}, report.Metadata.Verifier)
	if !at.IsZero() {
		require.Equal(t, at.UTC(), report.Metadata.VerifiedAt)
	}
	return report
}

func stepLayers(steps []Step) []Layer {
	var out []Layer
	for _, s := range steps {
		out = append(out, s.Layer)
	}
	return out
}

func TestReportOfAnEnvelopeRejection(t *testing.T) {
	v, err := NewVerifier(nil, Policy{})
	require.NoError(t, err)
	raw, nonce, _ := embeddedDocument(t, collateral.FormatV3)
	wrongNonce := slices.Clone(nonce)
	wrongNonce[0] ^= 1
	at := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.FixedZone("east", 3600))
	_, err = v.VerifyV3At(raw, wrongNonce, Pin{Project: "org/project"}, at)
	report := requireReport(t, err, LayerEnvelope, at)
	require.Nil(t, report.PartialFacts.Expected)
	require.Nil(t, report.PartialFacts.Measured, "nothing is measured from a document that doesn't parse")
}

func TestReportOfAProvenanceRejection(t *testing.T) {
	v, err := NewVerifier(nil, Policy{})
	require.NoError(t, err)
	nonce := make([]byte, document.NonceSize)
	hpkeKey := strings.Repeat("11", 32)
	raw, err := document.Build(document.BuildInput{
		Nonce: nonce, CollateralFormat: collateral.FormatV3,
		CryptoMaterial: []document.CryptoMaterialItem{
			{ID: document.CryptoMaterialIDTLS, Format: document.KeySPKIFPSHA256V1Format, Data: strings.Repeat("ab", 32)},
			{ID: document.CryptoMaterialIDHPKE, Format: document.KeyX25519HPKEV1Format, Data: hpkeKey},
		},
	}, func([64]byte) (string, []byte, error) { return document.SEVSNPReportV1Format, []byte("quote"), nil })
	require.NoError(t, err)
	_, err = v.VerifyV3(raw, nonce, Pin{Project: "org/project"})
	report := requireReport(t, err, LayerProvenance, time.Time{})
	require.Nil(t, report.PartialFacts.Expected, "rejected reference values are not expected facts")
	measured := report.PartialFacts.Measured
	require.NotNil(t, measured)
	require.Nil(t, measured.CPU, "the quote was never authenticated")
	require.Equal(t, strings.Repeat("ab", 32), measured.TLSPublicKeyFP)
	raw32, err := hex.DecodeString(hpkeKey)
	require.NoError(t, err)
	sum := sha256.Sum256(raw32)
	require.Equal(t, hex.EncodeToString(sum[:]), measured.HPKEPublicKeyFP)
	require.NotContains(t, measured.HPKEPublicKeyFP, hpkeKey, "a report carries no channel key")
}

// Embedding every reference value skips provenance, and the quote step still
// rejects a quote that isn't authentic.
func TestReportOfAQuoteRejection(t *testing.T) {
	inputs := embeddedInputs(t)
	v, err := newEmbeddedVerifier(inputs)
	require.NoError(t, err)
	raw, nonce, _ := embeddedDocument(t, collateral.FormatV3)
	_, err = v.VerifyV3(raw, nonce, Pin{})
	report := requireReport(t, err, LayerQuote, time.Time{})
	require.Equal(t, StepSkipped, report.Steps[1].Status)
	require.NotEmpty(t, report.Steps[1].Message)

	expected := report.PartialFacts.Expected
	require.NotNil(t, expected)
	require.Equal(t, SourceEmbedded, expected.Artifact.Source)
	require.Equal(t, "v0.15.5", expected.Artifact.Tag)
	require.Equal(t, expected.Artifact.Repo, expected.ConfigRepo)
	require.NotNil(t, expected.Config)
	require.Equal(t, SourceEmbedded, expected.Config.Source)
	require.Equal(t, embeddedConfigName, expected.Config.Name)
	require.NotNil(t, expected.Platform)
	require.Equal(t, SourceEmbedded, expected.Platform.Source)
	launch, err := measurement.ParseRegister(strings.Repeat("ab", runtime.MeasurementSize))
	require.NoError(t, err)
	require.Equal(t, measurement.ExpectedSEVSNP{Launch: &launch}, expected.CodeMeasurement, "the document's evidence names SEV-SNP")
	require.Nil(t, expected.Measurement, "the policy step never resolved the full expectation")

	require.NotNil(t, report.PartialFacts.Measured)
	require.Nil(t, report.PartialFacts.Measured.CPU, "an unauthenticated quote's registers are never shown")
}

func TestUsageErrorsHaveNoReport(t *testing.T) {
	v, err := NewVerifier(nil, Policy{})
	require.NoError(t, err)
	raw, nonce, _ := embeddedDocument(t, collateral.FormatV3)
	report, err := v.VerifyV3(raw, nonce, Pin{})
	require.Nil(t, report)
	var usage *UsageError
	require.ErrorAs(t, err, &usage)
	require.NotErrorAs(t, err, new(*VerificationError))
}

func TestReportCloneSharesNothing(t *testing.T) {
	register := measurement.Register{0xab}
	report := &VerificationReport{
		Steps: []Step{{Layer: LayerEnvelope, Status: StepFailed, Message: "m"}},
		PartialFacts: &PartialFacts{
			Expected: &ExpectedFacts{
				Config:          &ConfigVerification{Name: "config"},
				Platform:        &ArtifactVerification{Repo: "platform"},
				CodeMeasurement: measurement.ExpectedSEVSNP{Launch: &register},
				Measurement:     measurement.SEVSNP{Launch: register},
			},
			Measured: &MeasuredFacts{CPU: &CPUEvidence{Measurement: measurement.SEVSNP{Launch: register}}, TLSPublicKeyFP: "fp"},
		},
	}
	c := report.Clone()
	require.Equal(t, report, c)
	c.Steps[0].Message = "changed"
	c.PartialFacts.Expected.Config.Name = "changed"
	c.PartialFacts.Expected.Platform.Repo = "changed"
	*c.PartialFacts.Expected.CodeMeasurement.(measurement.ExpectedSEVSNP).Launch = measurement.Register{0xcd}
	c.PartialFacts.Measured.CPU.Measurement = nil
	c.PartialFacts.Measured.TLSPublicKeyFP = "changed"
	require.Equal(t, "m", report.Steps[0].Message)
	require.Equal(t, "config", report.PartialFacts.Expected.Config.Name)
	require.Equal(t, "platform", report.PartialFacts.Expected.Platform.Repo)
	require.Equal(t, measurement.Register{0xab}, register)
	require.NotNil(t, report.PartialFacts.Measured.CPU.Measurement)
	require.Equal(t, "fp", report.PartialFacts.Measured.TLSPublicKeyFP)
	require.Nil(t, (*VerificationReport)(nil).Clone())

	passed := &VerificationReport{VerifiedFacts: &VerifiedFacts{codeTag: "v1"}}
	c = passed.Clone()
	require.NotSame(t, passed.VerifiedFacts, c.VerifiedFacts)
	require.Equal(t, "v1", c.VerifiedFacts.CodeTag())
}

func TestHPKEPublicKeyFP(t *testing.T) {
	sum := sha256.Sum256([]byte{1, 2, 3})
	fp, ok := HPKEPublicKeyFP("010203")
	require.True(t, ok)
	require.Equal(t, hex.EncodeToString(sum[:]), fp)
	for _, bad := range []string{"", "not hex", "0"} {
		_, ok = HPKEPublicKeyFP(bad)
		require.False(t, ok, bad)
	}
}
