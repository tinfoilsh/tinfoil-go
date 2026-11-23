// Package verifytest builds verify.VerifiedFacts and verify.VerificationReport
// values for this module's tests without verifying a document.
package verifytest

import (
	"errors"
	"time"

	"github.com/tinfoilsh/tinfoil-go/internal/sdkinfo"
	"github.com/tinfoilsh/tinfoil-go/internal/verifyhook"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

// Fields are the facts that the verification reports.
type Fields = verifyhook.Fields

// New returns verified facts that report f.
func New(f Fields) *verify.VerifiedFacts {
	return verifyhook.NewVerifiedFacts(f).(*verify.VerifiedFacts)
}

// NewReport returns the report of a verification that passed every step and
// proved f, made now.
func NewReport(f Fields) *verify.VerificationReport {
	return Passed(New(f))
}

// Passed returns the report of a verification that passed every step and
// proved facts, made now.
func Passed(facts *verify.VerifiedFacts) *verify.VerificationReport {
	return &verify.VerificationReport{
		Steps: []verify.Step{
			{Layer: verify.LayerEnvelope, Status: verify.StepPassed},
			{Layer: verify.LayerProvenance, Status: verify.StepPassed},
			{Layer: verify.LayerQuote, Status: verify.StepPassed},
			{Layer: verify.LayerPolicy, Status: verify.StepPassed},
		},
		VerifiedFacts: facts,
		Metadata:      metadata(),
	}
}

// Rejected returns the VerificationError of a verification that the quote
// step rejected with message, after the envelope and provenance steps
// passed, made now.
func Rejected(message string) *verify.VerificationError {
	return &verify.VerificationError{
		Layer: verify.LayerQuote,
		Err:   errors.New(message),
		Report: &verify.VerificationReport{
			Steps: []verify.Step{
				{Layer: verify.LayerEnvelope, Status: verify.StepPassed},
				{Layer: verify.LayerProvenance, Status: verify.StepPassed},
				{Layer: verify.LayerQuote, Status: verify.StepFailed, Message: message},
				{Layer: verify.LayerPolicy, Status: verify.StepNotRun},
			},
			PartialFacts: &verify.PartialFacts{
				Expected: &verify.ExpectedFacts{},
				Measured: &verify.MeasuredFacts{},
			},
			Metadata: metadata(),
		},
	}
}

func metadata() verify.VerificationMetadata {
	return verify.VerificationMetadata{
		Verifier:   verify.SoftwareIdentity{Name: sdkinfo.Name, Version: sdkinfo.Version()},
		VerifiedAt: time.Now().UTC(),
	}
}
