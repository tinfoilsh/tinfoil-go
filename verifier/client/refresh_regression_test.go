package client

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestTransportDiscardsSnapshotRefreshedDuringBuild(t *testing.T) {
	s := &SecureClient{state: testState(time.Now().Add(time.Hour), "old"), verify: func() (*verificationState, error) {
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
	s := &SecureClient{state: testState(time.Now().Add(time.Hour), "key"), verify: func() (*verificationState, error) {
		t.Error("re-verification cannot make a plaintext URL acceptable")
		return nil, ErrNoTLS
	}}
	hc, err := s.HTTPClient()
	require.NoError(t, err)
	_, err = hc.Get("http://enclave.example")
	require.ErrorIs(t, err, ErrNoTLS)
}
