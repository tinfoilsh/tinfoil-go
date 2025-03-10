package tinfoil

import (
	"os"
)

// GroundTruth represents the "known good" verified state of the enclave
type GroundTruth struct {
	CertFingerprint []byte
	Digest          string
	Measurement     string
}

// Helper function to compare byte slices
func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Helper function to get environment variable with default
func getEnvDefault(key, defaultValue string) string {
	value, exists := os.LookupEnv(key)
	if !exists {
		return defaultValue
	}
	return value
}
