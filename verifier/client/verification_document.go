package client

import (
	"runtime/debug"
	"strings"
	"time"

	"github.com/tinfoilsh/tinfoil-go/verifier/attestation"
)

const (
	verificationDocumentSchemaVersion = 1
	verifierName                      = "tinfoil-go"
	verifierModulePath                = "github.com/tinfoilsh/tinfoil-go"
	// Version is the Tinfoil Go SDK release version.
	Version = "0.15.0"
)

var verificationTime = time.Now

// SoftwareIdentity identifies software involved in verification.
type SoftwareIdentity struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// VerificationStepState describes one verification step.
type VerificationStepState struct {
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

// VerificationSteps describes the checks represented by a verification document.
type VerificationSteps struct {
	FetchDigest         VerificationStepState `json:"fetchDigest"`
	VerifyCode          VerificationStepState `json:"verifyCode"`
	VerifyEnclave       VerificationStepState `json:"verifyEnclave"`
	CompareMeasurements VerificationStepState `json:"compareMeasurements"`
	VerifyCertificate   VerificationStepState `json:"verifyCertificate"`
}

// DocumentEnclaveMeasurement contains the observed measurement and attested keys.
type DocumentEnclaveMeasurement struct {
	Measurement             *attestation.Measurement `json:"measurement"`
	TLSPublicKeyFingerprint string                   `json:"tlsPublicKeyFingerprint,omitempty"`
	HPKEPublicKey           string                   `json:"hpkePublicKey,omitempty"`
}

// VerificationDocument is the Verification Center-compatible result of verification.
type VerificationDocument struct {
	SchemaVersion          int                              `json:"schemaVersion"`
	ConfigRepo             string                           `json:"configRepo"`
	EnclaveHost            string                           `json:"enclaveHost"`
	ReleaseTag             string                           `json:"releaseTag,omitempty"`
	ReleaseDigest          string                           `json:"releaseDigest"`
	CodeMeasurement        *attestation.Measurement         `json:"codeMeasurement"`
	EnclaveMeasurement     DocumentEnclaveMeasurement       `json:"enclaveMeasurement"`
	TLSPublicKey           string                           `json:"tlsPublicKey"`
	HPKEPublicKey          string                           `json:"hpkePublicKey"`
	HardwareMeasurement    *attestation.HardwareMeasurement `json:"hardwareMeasurement,omitempty"`
	CodeFingerprint        string                           `json:"codeFingerprint"`
	EnclaveFingerprint     string                           `json:"enclaveFingerprint"`
	SelectedRouterEndpoint string                           `json:"selectedRouterEndpoint"`
	SecurityVerified       bool                             `json:"securityVerified"`
	Verifier               SoftwareIdentity                 `json:"verifier"`
	VerifiedAt             string                           `json:"verifiedAt,omitempty"`
	Steps                  VerificationSteps                `json:"steps"`
}

func currentVerifierIdentity() SoftwareIdentity {
	return SoftwareIdentity{Name: verifierName, Version: currentVerifierVersion()}
}

func currentVerifierVersion() string {
	return verifierVersion(debug.ReadBuildInfo())
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

func successfulStep() VerificationStepState {
	return VerificationStepState{Status: "success"}
}

func skippedStep() VerificationStepState {
	return VerificationStepState{Status: "skipped"}
}

func newVerificationDocument(groundTruth *GroundTruth) *VerificationDocument {
	fetchDigest := skippedStep()
	verifyCode := successfulStep()
	if groundTruth.DigestFetched {
		fetchDigest = successfulStep()
	}
	if groundTruth.Digest == pinnedNoDigest {
		verifyCode = skippedStep()
	}
	return &VerificationDocument{
		SchemaVersion:   verificationDocumentSchemaVersion,
		ConfigRepo:      groundTruth.ConfigRepo,
		EnclaveHost:     groundTruth.EnclaveHost,
		ReleaseTag:      groundTruth.ReleaseTag,
		ReleaseDigest:   groundTruth.Digest,
		CodeMeasurement: groundTruth.CodeMeasurement,
		EnclaveMeasurement: DocumentEnclaveMeasurement{
			Measurement:             groundTruth.EnclaveMeasurement,
			TLSPublicKeyFingerprint: groundTruth.TLSPublicKey,
			HPKEPublicKey:           groundTruth.HPKEPublicKey,
		},
		TLSPublicKey:           groundTruth.TLSPublicKey,
		HPKEPublicKey:          groundTruth.HPKEPublicKey,
		HardwareMeasurement:    groundTruth.HardwareMeasurement,
		CodeFingerprint:        groundTruth.CodeFingerprint,
		EnclaveFingerprint:     groundTruth.EnclaveFingerprint,
		SelectedRouterEndpoint: groundTruth.EnclaveHost,
		SecurityVerified:       true,
		Verifier:               groundTruth.Verifier,
		VerifiedAt:             groundTruth.VerifiedAt,
		Steps: VerificationSteps{
			FetchDigest:         fetchDigest,
			VerifyCode:          verifyCode,
			VerifyEnclave:       successfulStep(),
			CompareMeasurements: successfulStep(),
			VerifyCertificate:   successfulStep(),
		},
	}
}

func (s *SecureClient) setVerifiedState(groundTruth *GroundTruth) {
	clonedGroundTruth := cloneGroundTruth(groundTruth)
	s.stateMu.Lock()
	if clonedGroundTruth.EnclaveHost != "" {
		s.enclave = clonedGroundTruth.EnclaveHost
	}
	s.groundTruth = clonedGroundTruth
	s.verificationDocument = newVerificationDocument(clonedGroundTruth)
	s.stateMu.Unlock()
}

func cloneVerificationDocument(document *VerificationDocument) *VerificationDocument {
	if document == nil {
		return nil
	}
	cloned := *document
	cloned.CodeMeasurement = cloneMeasurement(document.CodeMeasurement)
	cloned.EnclaveMeasurement.Measurement = cloneMeasurement(document.EnclaveMeasurement.Measurement)
	if document.HardwareMeasurement != nil {
		hardware := *document.HardwareMeasurement
		cloned.HardwareMeasurement = &hardware
	}
	return &cloned
}

// Clone returns a deep copy of the verification document.
func (document *VerificationDocument) Clone() *VerificationDocument {
	return cloneVerificationDocument(document)
}

func cloneMeasurement(measurement *attestation.Measurement) *attestation.Measurement {
	if measurement == nil {
		return nil
	}
	cloned := *measurement
	cloned.Registers = append([]string(nil), measurement.Registers...)
	return &cloned
}

func cloneGroundTruth(groundTruth *GroundTruth) *GroundTruth {
	if groundTruth == nil {
		return nil
	}
	cloned := *groundTruth
	cloned.CodeMeasurement = cloneMeasurement(groundTruth.CodeMeasurement)
	cloned.EnclaveMeasurement = cloneMeasurement(groundTruth.EnclaveMeasurement)
	if groundTruth.HardwareMeasurement != nil {
		hardware := *groundTruth.HardwareMeasurement
		cloned.HardwareMeasurement = &hardware
	}
	return &cloned
}
