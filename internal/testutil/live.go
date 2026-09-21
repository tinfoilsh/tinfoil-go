package testutil

import (
	"os"
	"testing"
)

// RequireLive must be the first call in tests named TestLive* that contact
// external services; the gate keeps default runs local and the prefix selects live CI.
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
