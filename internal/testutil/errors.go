package testutil

import (
	"errors"
	"testing"

	"github.com/tinfoilsh/tinfoil-go/internal/errs"
)

// RequireCategory fails t unless err is in category and in no other SDK
// category. A nil category requires that err is in none, as the caller's own
// cancellation must be.
func RequireCategory(t testing.TB, err, category error) {
	t.Helper()
	if err == nil {
		t.Fatalf("got no error, want one in category %v", category)
	}
	for _, c := range []error{errs.ErrConfiguration, errs.ErrNetwork, errs.ErrAttestation} {
		if got, want := errors.Is(err, c), c == category; got != want {
			t.Fatalf("errors.Is(err, %v) = %v, want %v; err: %v", c, got, want, err)
		}
	}
}
