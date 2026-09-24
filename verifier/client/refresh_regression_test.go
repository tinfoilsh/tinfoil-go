package client

import (
	"errors"
	"net/http"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"
)

func TestTransportDiscardsSnapshotRefreshedDuringBuild(t *testing.T) {
	s := &SecureClient{state: testEnclaveState(time.Now().Add(time.Hour), "old"), verify: func() (*VerifiedDocumentV3, error) {
		return testState(time.Now().Add(time.Hour), "new"), nil
	}}
	var built, sent []string
	transport, err := s.NewTransport(func(verified *VerifiedDocumentV3) (http.RoundTripper, error) {
		built = append(built, verified.CryptoMaterial[0].Data)
		if verified.CryptoMaterial[0].Data == "old" {
			_, err := s.Verify()
			require.NoError(t, err)
		}
		return roundTripFunc(func(*http.Request) (*http.Response, error) {
			sent = append(sent, verified.CryptoMaterial[0].Data)
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
	s := &SecureClient{state: testEnclaveState(time.Now().Add(time.Hour), "key"), verify: func() (*VerifiedDocumentV3, error) {
		t.Error("re-verification cannot make a plaintext URL acceptable")
		return nil, errNoTLS
	}}
	hc, err := s.HTTPClient()
	require.NoError(t, err)
	_, err = hc.Get("http://enclave.example")
	require.ErrorIs(t, err, errNoTLS)
}

func TestRefreshPublishesVerificationAndTransportTogether(t *testing.T) {
	for _, buildErr := range []error{nil, errors.New("transport construction failed")} {
		t.Run(errorString(buildErr), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s := &SecureClient{state: testEnclaveState(time.Now().Add(time.Hour), "old"), verify: func() (*VerifiedDocumentV3, error) {
					return testState(time.Now().Add(time.Hour), "new"), nil
				}}
				release := make(chan struct{})
				transport, err := s.NewTransport(func(verified *VerifiedDocumentV3) (http.RoundTripper, error) {
					if verified.CodeTag == "new" {
						<-release
						if buildErr != nil {
							return nil, buildErr
						}
					}
					return roundTripFunc(func(*http.Request) (*http.Response, error) {
						response := testResponse()
						response.Header.Set("Key", verified.CodeTag)
						return response, nil
					}), nil
				}, nil)
				require.NoError(t, err)
				finished := make(chan error, 1)
				go func() { _, err := s.Verify(); finished <- err }()
				synctest.Wait()
				require.Equal(t, "old", s.Verification().CodeTag)
				req, _ := http.NewRequest(http.MethodGet, "https://enclave.example", nil)
				resp, err := transport.RoundTrip(req)
				require.NoError(t, err)
				require.Equal(t, "old", resp.Header.Get("Key"))
				close(release)
				require.ErrorIs(t, <-finished, buildErr)
				expected := "new"
				if buildErr != nil {
					expected = "old"
				}
				require.Equal(t, expected, s.Verification().CodeTag)
				resp, err = transport.RoundTrip(req)
				require.NoError(t, err)
				require.Equal(t, expected, resp.Header.Get("Key"))
			})
		})
	}
}

func TestHTTPClientReusesTransportConfiguration(t *testing.T) {
	s := &SecureClient{state: testEnclaveState(time.Now().Add(time.Hour), "key")}
	first, err := s.HTTPClient()
	require.NoError(t, err)
	second, err := s.HTTPClient()
	require.NoError(t, err)
	require.Same(t, first.Transport, second.Transport)
	require.Len(t, s.state.transports, 1)
}
