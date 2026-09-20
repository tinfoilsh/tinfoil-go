package testutil

import (
	"os"
	"testing"
)

// RequireLive selects tests that contact external services and checks their configuration.
func RequireLive(t *testing.T, requiredEnv ...string) {
	t.Helper()
	if testing.Short() || os.Getenv("RUN_TINFOIL_INTEGRATION") != "true" {
		t.Skip("live test; set RUN_TINFOIL_INTEGRATION=true without -short to run")
	}
	for _, name := range requiredEnv {
		if os.Getenv(name) == "" {
			t.Fatalf("%s must be set for this live test", name)
		}
	}
}
