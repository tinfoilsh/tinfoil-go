package enclave

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

func TestVerificationFetchStillTimesOut(t *testing.T) {
	original := http.DefaultClient
	t.Cleanup(func() { http.DefaultClient = original })
	synctest.Test(t, func(t *testing.T) {
		var requests int
		http.DefaultClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			requests++
			<-req.Context().Done()
			return nil, req.Context().Err()
		})}
		start := time.Now()
		client, err := New(Config{Host: "enclave.example", Repo: "org/repo"})
		require.NoError(t, err)
		_, err = client.Verify()
		require.ErrorIs(t, err, context.DeadlineExceeded)
		var fetch *NetworkError
		require.ErrorAs(t, err, &fetch)
		require.True(t, strings.HasPrefix(err.Error(), "network error: "), "verification fetch retains its SDK category prefix")
		require.Equal(t, 2, requests)
		require.Equal(t, 61*time.Second, time.Since(start), "two bounded 30-second fetches and one recovery delay")
	})
}

func TestRejectedDocumentIsAttestationError(t *testing.T) {
	original := http.DefaultClient
	t.Cleanup(func() { http.DefaultClient = original })
	synctest.Test(t, func(t *testing.T) {
		http.DefaultClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			resp := testResponse()
			resp.Body = io.NopCloser(strings.NewReader("{}"))
			return resp, nil
		})}
		client, err := New(Config{Host: "enclave.example", Repo: "org/repo"})
		require.NoError(t, err)
		_, err = client.Verify()
		var attestation *AttestationError
		require.ErrorAs(t, err, &attestation)
		var rejected *verify.VerificationError
		require.ErrorAs(t, err, &rejected, "verify's error remains the cause")
		require.True(t, strings.HasPrefix(err.Error(), "attestation error: "), err.Error())
	})
}
