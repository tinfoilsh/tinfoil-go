package client

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Models a deadline whose timer callback has not yet closed Done or set Err.
type delayedDeadlineContext struct {
	context.Context
	deadline time.Time
}

func (c delayedDeadlineContext) Deadline() (time.Time, bool) { return c.deadline, true }

func TestRefreshRejectsElapsedDeadlineBeforeTimerRuns(t *testing.T) {
	s := &SecureClient{verify: func(context.Context) (*verificationState, error) {
		return testState(time.Now().Add(time.Hour), "key"), nil
	}}
	call := &verificationCall{
		ctx:  delayedDeadlineContext{Context: context.Background(), deadline: time.Now().Add(-time.Second)},
		done: make(chan struct{}),
	}
	s.refresh(call, func() {})
	require.ErrorIs(t, call.err, context.DeadlineExceeded)
	require.Nil(t, call.state)
	require.Nil(t, s.GroundTruth())
}

func TestTransportDiscardsSnapshotRefreshedDuringBuild(t *testing.T) {
	s := &SecureClient{state: testState(time.Now().Add(time.Hour), "old"), verify: func(context.Context) (*verificationState, error) {
		return testState(time.Now().Add(time.Hour), "new"), nil
	}}
	var built, sent []string
	transport, err := s.NewTransport(func(gt *GroundTruth) (http.RoundTripper, error) {
		built = append(built, gt.TLSPublicKey)
		if gt.TLSPublicKey == "old" {
			_, err := s.Verify()
			require.NoError(t, err)
		}
		return roundTripFunc(func(*http.Request) (*http.Response, error) {
			sent = append(sent, gt.TLSPublicKey)
			return testResponse(), nil
		}), nil
	}, nil)
	require.NoError(t, err)
	require.Equal(t, []string{"old", "new"}, built, "discard the obsolete build before admitting requests")
	req, _ := http.NewRequest(http.MethodGet, "https://enclave.example", nil)
	_, err = transport.RoundTrip(req)
	require.NoError(t, err)
	require.Equal(t, []string{"new"}, sent)
}

func TestPlaintextRequestDoesNotRefresh(t *testing.T) {
	s := &SecureClient{state: testState(time.Now().Add(time.Hour), "key"), verify: func(context.Context) (*verificationState, error) {
		t.Error("re-verification cannot make a plaintext URL acceptable")
		return nil, ErrNoTLS
	}}
	hc, err := s.HTTPClient()
	require.NoError(t, err)
	_, err = hc.Get("http://enclave.example")
	require.ErrorIs(t, err, ErrNoTLS)
}
