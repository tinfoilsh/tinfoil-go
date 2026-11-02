package enclave

import (
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

func TestInitializationRecovery(t *testing.T) {
	firstCause, lastCause := errors.New("first attempt"), errors.New("last attempt")
	for _, tc := range []struct {
		name        string
		first, last error
		attempts    int
	}{
		{"fetch then success", &NetworkError{Err: firstCause}, nil, 2},
		{"attestation then success", &AttestationError{Err: firstCause}, nil, 2},
		{"both attempts fail", &NetworkError{Err: firstCause}, &AttestationError{Err: lastCause}, 2},
		{"configuration", &ConfigurationError{Err: firstCause}, nil, 1},
		{"native error", firstCause, nil, 1},
		{"native error with fetch diagnostics", errors.Join(firstCause, &NetworkError{Err: lastCause}), nil, 1},
		{"configuration among causes", errors.Join(&NetworkError{Err: lastCause}, &ConfigurationError{Err: firstCause}), nil, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s := &Enclave{}
				var attempts int
				s.fetch = func() (*verify.Verification, error) {
					attempts++
					if attempts == 1 {
						return testState(time.Now().Add(time.Hour), "rejected"), tc.first
					}
					return testState(time.Now().Add(time.Hour), "fresh"), tc.last
				}
				start := time.Now()
				verified, err := s.Verify()
				require.Equal(t, tc.attempts, attempts)
				require.Equal(t, time.Duration(attempts-1)*time.Second, time.Since(start))
				if attempts == 2 && tc.last == nil {
					require.NoError(t, err)
					require.Equal(t, "fresh", verified.CodeTag())
				} else {
					require.ErrorIs(t, err, firstCause)
					if tc.last != nil {
						require.ErrorIs(t, err, lastCause)
					}
					require.Nil(t, verified)
				}
			})
		})
	}
}
