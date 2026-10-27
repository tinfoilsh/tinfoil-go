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

func TestRefreshWaitersCancelIndependentlyWithoutVerificationTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		s := NewTestHandle("enclave.example", nil, func() (*verify.Verification, error) {
			<-release
			return testState(time.Now().Add(time.Hour), "key"), nil
		})
		ctx, cancel := context.WithCancel(context.Background())
		canceled, waiting := make(chan error, 1), make(chan error, 1)
		go func() { _, err := s.verifiedState(ctx, false, verificationRetries); canceled <- err }()
		go func() { _, err := verifyNow(s); waiting <- err }()
		synctest.Wait()
		cancel()
		require.ErrorIs(t, <-canceled, context.Canceled)
		time.Sleep(time.Minute)
		select {
		case <-waiting:
			t.Fatal("shared verification must survive caller cancellation and has no SDK timeout")
		default:
		}
		close(release)
		require.NoError(t, <-waiting)
		require.NotNil(t, current(s))
	})
}

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
		client, err := NewHandle(Config{Host: "enclave.example", Repo: "org/repo"})
		require.NoError(t, err)
		_, err = verifyNow(client)
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
		client, err := NewHandle(Config{Host: "enclave.example", Repo: "org/repo"})
		require.NoError(t, err)
		_, err = verifyNow(client)
		var attestation *AttestationError
		require.ErrorAs(t, err, &attestation)
		var rejected *verify.VerificationError
		require.ErrorAs(t, err, &rejected, "verify's error remains the cause")
		require.True(t, strings.HasPrefix(err.Error(), "attestation error: "), err.Error())
	})
}
