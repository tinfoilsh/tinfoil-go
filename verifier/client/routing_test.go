package client

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCachedEnclavesRemainIndependent(t *testing.T) {
	attempts := make(map[string]int)
	failed := errors.New("verification failed")
	s, err := NewSecureClient("a.example", "org/repo", nil)
	require.NoError(t, err)
	s.verify = func(enclave string) (*VerifiedDocumentV3, error) {
		attempts[enclave]++
		if enclave == "bad.example" {
			return nil, failed
		}
		return testState(time.Now().Add(time.Hour), enclave), nil
	}
	transport, err := s.NewTransport(func(verified *VerifiedDocumentV3) (http.RoundTripper, error) {
		return roundTripFunc(func(*http.Request) (*http.Response, error) {
			resp := testResponse()
			resp.Header.Set("Enclave", verified.EnclaveHost)
			return resp, nil
		}), nil
	}, nil)
	require.NoError(t, err)
	initial := s.enclaves["a.example"].state
	adapter := transport.(*refreshingTransport)
	for _, target := range []string{"b.example", "bad.example", "a.example"} {
		state, err := s.prepareTransport(context.Background(), target, adapter, verificationRetries)
		if target == "bad.example" {
			require.ErrorIs(t, err, failed)
			require.NotContains(t, s.enclaves, target)
			continue
		}
		require.NoError(t, err)
		req, _ := http.NewRequest(http.MethodGet, "https://"+target, nil)
		resp, err := state.transports[adapter].RoundTrip(req)
		require.NoError(t, err)
		require.Equal(t, target, resp.Header.Get("Enclave"))
		resp.Body.Close()
	}
	require.Equal(t, map[string]int{"a.example": 1, "b.example": 1, "bad.example": 1}, attempts)
	require.Same(t, initial, s.enclaves["a.example"].state)
	require.Equal(t, "a.example", s.Enclave(), "preparing another enclave does not select it")
	s.invalidate(initial)
	require.True(t, s.enclaves["b.example"].state.valid())
}
