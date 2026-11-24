package verify

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"

	"github.com/tinfoilsh/tinfoil-go/verify/document"
	"github.com/tinfoilsh/tinfoil-go/verify/measurement"
)

// VerificationReport describes one verification of an attestation document,
// step by step, and what each step established. VerifyV3 returns one for a
// document that it accepts, and a VerificationError carries one for a
// document that it rejects, so that a caller can show what happened either
// way.
//
// A report is plain data: code that hands one to several holders, as the
// SDK's clients do, hands each a Clone.
type VerificationReport struct {
	// Steps are the four layers in order: envelope, provenance, quote and
	// policy, each of which passed, failed, was skipped or did not run.
	Steps []Step
	// VerifiedFacts is set if and only if no step failed. It is the only
	// part of a report that carries the keys that a channel binds to.
	VerifiedFacts *VerifiedFacts
	// PartialFacts is set if and only if a step failed. It holds what the
	// steps before the failure established.
	PartialFacts *PartialFacts
	// Metadata describes the verification rather than the document.
	Metadata VerificationMetadata
}

// Step is the outcome of one verification layer.
type Step struct {
	Layer  Layer
	Status StepStatus
	// Message is the error text for a failed step, and the reason for a
	// skipped one; it is empty otherwise.
	Message string
}

// StepStatus is the outcome of a Step.
type StepStatus string

const (
	// StepPassed means that the layer accepted the document.
	StepPassed StepStatus = "passed"
	// StepFailed means that the layer rejected the document.
	StepFailed StepStatus = "failed"
	// StepSkipped means that the layer had nothing to check, as for
	// provenance when the caller embeds every reference value.
	StepSkipped StepStatus = "skipped"
	// StepNotRun means that an earlier layer rejected the document.
	StepNotRun StepStatus = "not_run"
)

// Failed returns the step that failed, or ok false when none did.
func (r *VerificationReport) Failed() (step Step, ok bool) {
	if r == nil {
		return Step{}, false
	}
	for _, s := range r.Steps {
		if s.Status == StepFailed {
			return s, true
		}
	}
	return Step{}, false
}

// Clone returns a copy of r that shares nothing that a holder can change
// with r, or nil for nil.
func (r *VerificationReport) Clone() *VerificationReport {
	if r == nil {
		return nil
	}
	c := *r
	c.Steps = slices.Clone(r.Steps)
	if r.VerifiedFacts != nil {
		// Its fields can't be changed, and its accessors return copies.
		facts := *r.VerifiedFacts
		c.VerifiedFacts = &facts
	}
	c.PartialFacts = r.PartialFacts.clone()
	return &c
}

// PartialFacts are what a rejected verification established before the
// step that failed. Every fact in them is authenticated, except the key
// fingerprints, which MeasuredFacts describes.
type PartialFacts struct {
	// Expected is nil unless the provenance step passed or was skipped.
	Expected *ExpectedFacts
	// Measured is nil unless the envelope step passed.
	Measured *MeasuredFacts
}

func (p *PartialFacts) clone() *PartialFacts {
	if p == nil {
		return nil
	}
	c := PartialFacts{Expected: p.Expected.clone(), Measured: p.Measured.clone()}
	return &c
}

// ExpectedFacts are the reference values that the provenance step accepted:
// what the enclave should be running.
type ExpectedFacts struct {
	// ConfigRepo identifies the selected code or runtime, without version
	// pins.
	ConfigRepo string
	// Artifact is the code release, or the runtime for a config-based
	// verification.
	Artifact ArtifactVerification
	// Config is the config that a config-based verification accepted, and
	// nil for a code release.
	Config *ConfigVerification
	// Platform is the platform endorsement artifact that a config-based
	// verification accepted, and nil for a code release.
	Platform *ArtifactVerification
	// CodeMeasurement is the registers that the release fixes on the
	// platform that the document's CPU evidence names, with nil for a
	// register that the release leaves to the platform. It is nil if the
	// release fixes nothing usable on that platform.
	CodeMeasurement measurement.Expected
	// Measurement is every register that the quote must attest: the code
	// measurement, the verifier's pinned registers and, for a code release
	// on TDX, the platform registers (MRTD and RTMR0) that the platform
	// endorsements supply for the quote's machine. It is set once the policy
	// step resolved every register, even if a later check of that step
	// failed, and nil otherwise.
	Measurement measurement.Measurement
}

func (e *ExpectedFacts) clone() *ExpectedFacts {
	if e == nil {
		return nil
	}
	c := *e
	if e.Config != nil {
		config := *e.Config
		c.Config = &config
	}
	if e.Platform != nil {
		platform := *e.Platform
		c.Platform = &platform
	}
	if e.CodeMeasurement != nil {
		c.CodeMeasurement = e.CodeMeasurement.Clone()
	}
	return &c
}

// MeasuredFacts are what the document and its hardware evidence claim.
type MeasuredFacts struct {
	// CPU is set only once the quote step passed, so what it holds came
	// from the hardware.
	CPU *CPUEvidence
	// TLSPublicKeyFP and HPKEPublicKeyFP identify the channel keys that the
	// document endorses, or are empty when it endorses none. Only the policy
	// step binds them to the enclave, so in a rejected report they are
	// always unverified. TLSPublicKeyFP is the SPKI SHA-256 fingerprint that
	// VerifiedFacts.TLSPublicKeyFP returns, and HPKEPublicKeyFP is the
	// lowercase-hex SHA-256 of the HPKE public key's bytes, never the key.
	TLSPublicKeyFP  string
	HPKEPublicKeyFP string
}

func (m *MeasuredFacts) clone() *MeasuredFacts {
	if m == nil {
		return nil
	}
	c := *m
	if m.CPU != nil {
		cpu := *m.CPU
		c.CPU = &cpu
	}
	return &c
}

// CPUEvidence is what the CPU's authenticated quote proves.
type CPUEvidence struct {
	// Measurement is every register that the hardware measured: a
	// measurement.SEVSNP or measurement.TDX value.
	Measurement measurement.Measurement
}

// HPKEPublicKeyFP returns the fingerprint that MeasuredFacts.HPKEPublicKeyFP
// reports for key, an HPKE public key in lowercase hex as the document
// endorses it: the lowercase-hex SHA-256 of the key's bytes. ok is false if
// key is not hex.
func HPKEPublicKeyFP(key string) (fp string, ok bool) {
	raw, err := hex.DecodeString(key)
	if err != nil || len(raw) == 0 {
		return "", false
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), true
}

// measuredKeys returns the key fingerprints that items endorse.
func measuredKeys(items []document.CryptoMaterialItem) *MeasuredFacts {
	m := &MeasuredFacts{}
	m.TLSPublicKeyFP, _ = CryptoMaterialData(items, document.CryptoMaterialIDTLS, document.KeySPKIFPSHA256V1Format)
	if key, ok := CryptoMaterialData(items, document.CryptoMaterialIDHPKE, document.KeyX25519HPKEV1Format); ok {
		m.HPKEPublicKeyFP, _ = HPKEPublicKeyFP(key)
	}
	return m
}

// reportBuilder records each step of a verification as verifyV3 runs it.
type reportBuilder struct {
	steps    []Step
	expected *ExpectedFacts
	measured *MeasuredFacts
}

// layers are the verification layers in the order that they run.
var layers = []Layer{LayerEnvelope, LayerProvenance, LayerQuote, LayerPolicy}

func newReportBuilder() *reportBuilder {
	b := &reportBuilder{steps: make([]Step, len(layers))}
	for i, layer := range layers {
		b.steps[i] = Step{Layer: layer, Status: StepNotRun}
	}
	return b
}

func (b *reportBuilder) set(layer Layer, status StepStatus, message string) {
	for i := range b.steps {
		if b.steps[i].Layer == layer {
			b.steps[i].Status, b.steps[i].Message = status, message
		}
	}
}

func (b *reportBuilder) passed(layer Layer) { b.set(layer, StepPassed, "") }

// passedAll reports a verification that every step accepted.
func (b *reportBuilder) passedAll(facts *VerifiedFacts, metadata VerificationMetadata) *VerificationReport {
	return &VerificationReport{Steps: slices.Clone(b.steps), VerifiedFacts: facts, Metadata: metadata}
}

// failed reports a verification that layer rejected with cause.
func (b *reportBuilder) failed(layer Layer, cause error, metadata VerificationMetadata) *VerificationReport {
	message := ""
	if cause != nil {
		message = cause.Error()
	}
	b.set(layer, StepFailed, message)
	return &VerificationReport{
		Steps:        slices.Clone(b.steps),
		PartialFacts: &PartialFacts{Expected: b.expected.clone(), Measured: b.measured.clone()},
		Metadata:     metadata,
	}
}
