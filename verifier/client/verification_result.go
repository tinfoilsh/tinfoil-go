package client

import (
	"github.com/tinfoilsh/tinfoil-go/internal/sdkinfo"
	"github.com/tinfoilsh/tinfoil-go/verifier/document"
	"github.com/tinfoilsh/tinfoil-go/verifier/measurement"
)

const (
	// Version is the Tinfoil Go SDK release version.
	Version = "0.16.0"
)

// SoftwareIdentity identifies software involved in verification.
type SoftwareIdentity struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func currentVerifierIdentity() SoftwareIdentity {
	return SoftwareIdentity{Name: sdkinfo.Name, Version: sdkinfo.Version()}
}

func cloneMeasurement(value *measurement.Measurement) *measurement.Measurement {
	if value == nil {
		return nil
	}
	cloned := *value
	cloned.Registers = append([]string(nil), value.Registers...)
	return &cloned
}

func cloneVerification(verified *VerifiedDocumentV3) *VerifiedDocumentV3 {
	if verified == nil {
		return nil
	}
	cloned := *verified
	cloned.CryptoMaterial = append([]document.CryptoMaterialItem(nil), verified.CryptoMaterial...)
	cloned.CodeMeasurement = cloneMeasurement(verified.CodeMeasurement)
	cloned.EnclaveMeasurement = cloneMeasurement(verified.EnclaveMeasurement)
	return &cloned
}
