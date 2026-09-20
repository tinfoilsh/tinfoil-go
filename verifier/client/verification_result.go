package client

import (
	"runtime/debug"
	"strings"

	"github.com/tinfoilsh/tinfoil-go/verifier/envelope"
	"github.com/tinfoilsh/tinfoil-go/verifier/measurement"
)

const (
	verifierName       = "tinfoil-go"
	verifierModulePath = "github.com/tinfoilsh/tinfoil-go"
	// Version is the Tinfoil Go SDK release version.
	Version = "0.15.0"
)

// SoftwareIdentity identifies software involved in verification.
type SoftwareIdentity struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func currentVerifierIdentity() SoftwareIdentity {
	return SoftwareIdentity{Name: verifierName, Version: verifierVersion(debug.ReadBuildInfo())}
}

func verifierVersion(info *debug.BuildInfo, ok bool) string {
	if !ok {
		return "unknown"
	}
	if info.Main.Path == verifierModulePath {
		return buildModuleVersion(&info.Main)
	}
	for _, dependency := range info.Deps {
		if dependency.Path == verifierModulePath {
			return buildModuleVersion(dependency)
		}
	}
	return "unknown"
}

func buildModuleVersion(module *debug.Module) string {
	if module.Replace != nil {
		module = module.Replace
	}
	version := strings.TrimPrefix(module.Version, "v")
	if version == "" || version == "(devel)" {
		return "devel"
	}
	return version
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
	cloned.CryptoMaterial = append([]envelope.CryptoMaterialItem(nil), verified.CryptoMaterial...)
	cloned.CodeMeasurement = cloneMeasurement(verified.CodeMeasurement)
	cloned.EnclaveMeasurement = cloneMeasurement(verified.EnclaveMeasurement)
	return &cloned
}
