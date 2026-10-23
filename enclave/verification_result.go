package enclave

import (
	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/document"
)

func cloneVerification(verified *verify.Verification) *verify.Verification {
	if verified == nil {
		return nil
	}
	cloned := *verified
	cloned.CryptoMaterial = append([]document.CryptoMaterialItem(nil), verified.CryptoMaterial...)
	// EnclaveMeasurement holds its registers by value, so the copy is already
	// independent.
	if verified.CodeMeasurement != nil {
		cloned.CodeMeasurement = verified.CodeMeasurement.Clone()
	}
	if verified.Config != nil {
		config := *verified.Config
		cloned.Config = &config
	}
	if verified.Runtime != nil {
		runtime := *verified.Runtime
		cloned.Runtime = &runtime
	}
	if verified.Platform != nil {
		platform := *verified.Platform
		cloned.Platform = &platform
	}
	return &cloned
}
