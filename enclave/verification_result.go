package enclave

import (
	"github.com/tinfoilsh/tinfoil-go/document"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/measurement"
)

func cloneMeasurement(value *measurement.Measurement) *measurement.Measurement {
	if value == nil {
		return nil
	}
	cloned := *value
	cloned.Registers = append([]string(nil), value.Registers...)
	return &cloned
}

func cloneVerification(verified *verify.Verification) *verify.Verification {
	if verified == nil {
		return nil
	}
	cloned := *verified
	cloned.CryptoMaterial = append([]document.CryptoMaterialItem(nil), verified.CryptoMaterial...)
	cloned.CodeMeasurement = cloneMeasurement(verified.CodeMeasurement)
	cloned.EnclaveMeasurement = cloneMeasurement(verified.EnclaveMeasurement)
	return &cloned
}
