package transport

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	ehbpprotocol "github.com/tinfoilsh/encrypted-http-body-protocol/protocol"
	"github.com/tinfoilsh/tinfoil-go/internal/errs"
	"github.com/tinfoilsh/tinfoil-go/internal/testutil"
)

// failingBody returns its data, then err.
type failingBody struct {
	data     *strings.Reader
	err      error
	closeErr error
}

func (b *failingBody) Read(p []byte) (int, error) {
	if b.data.Len() > 0 {
		return b.data.Read(p)
	}
	return 0, b.err
}

func (b *failingBody) Close() error { return b.closeErr }

// readWriteBody is the body of a protocol switch.
type readWriteBody struct {
	io.Reader
	written []byte
}

func (b *readWriteBody) Write(p []byte) (int, error) {
	b.written = append(b.written, p...)
	return len(p), nil
}
func (*readWriteBody) Close() error { return nil }

func TestBackstopClassifiesEachRequestError(t *testing.T) {
	reset := errors.New("connection reset by peer")
	live := context.Background()
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	for name, tc := range map[string]struct {
		ctx      context.Context
		err      error
		category error
	}{
		"a refused connection":        {live, errors.New("connection refused"), errs.ErrNetwork},
		"an SDK error":                {live, errs.Attestation(reset), errs.ErrAttestation},
		"a configuration error":       {cancelled, errs.Configuration(reset), errs.ErrConfiguration},
		"the caller's cancellation":   {cancelled, context.Canceled, nil},
		"a failure before the cancel": {cancelled, reset, errs.ErrNetwork},
	} {
		t.Run(name, func(t *testing.T) {
			rt := WithBackstop(roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, tc.err }))
			req, err := http.NewRequestWithContext(tc.ctx, http.MethodGet, "https://enclave.example/", nil)
			require.NoError(t, err)
			_, err = rt.RoundTrip(req)
			testutil.RequireCategory(t, err, tc.category)
			require.ErrorIs(t, err, tc.err)
		})
	}
}

func TestBackstopClassifiesResponseBodyErrors(t *testing.T) {
	reset := errors.New("connection reset by peer")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	body := &failingBody{data: strings.NewReader("partial"), err: reset, closeErr: errors.New("close failed")}
	rt := WithBackstop(roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: body}, nil
	}))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://enclave.example/", nil)
	require.NoError(t, err)
	resp, err := rt.RoundTrip(req)
	require.NoError(t, err)
	data, err := io.ReadAll(resp.Body)
	require.Equal(t, "partial", string(data))
	testutil.RequireCategory(t, err, errs.ErrNetwork)
	require.ErrorIs(t, err, reset)
	testutil.RequireCategory(t, resp.Body.Close(), errs.ErrNetwork)

	body.err = errs.Attestation(reset)
	_, err = resp.Body.Read(make([]byte, 1))
	testutil.RequireCategory(t, err, errs.ErrAttestation)

	cancel()
	body.err = context.Canceled
	_, err = resp.Body.Read(make([]byte, 1))
	testutil.RequireCategory(t, err, nil)
	require.Same(t, context.Canceled, err, "the caller's cancellation, as it is")

	body.err = io.EOF
	_, err = resp.Body.Read(make([]byte, 1))
	require.Same(t, io.EOF, err, "the end of the body is no error")
	body.closeErr = nil
	require.NoError(t, resp.Body.Close())
}

func TestBackstopKeepsABodyThatCanBeWritten(t *testing.T) {
	switched := &readWriteBody{Reader: strings.NewReader("from the server")}
	rt := WithBackstop(roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusSwitchingProtocols, Header: make(http.Header), Body: switched}, nil
	}))
	resp, err := rt.RoundTrip(newRequest(t, http.MethodGet, "https://enclave.example/", nil))
	require.NoError(t, err)
	rw, ok := resp.Body.(io.ReadWriteCloser)
	require.True(t, ok, "net/http's callers write to a switched protocol's body")
	_, err = rw.Write([]byte("to the server"))
	require.NoError(t, err)
	require.Equal(t, "to the server", string(switched.written))

	for _, body := range []io.ReadCloser{nil, http.NoBody} {
		rt := WithBackstop(roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusNoContent, Header: make(http.Header), Body: body}, nil
		}))
		resp, err := rt.RoundTrip(newRequest(t, http.MethodGet, "https://enclave.example/", nil))
		require.NoError(t, err)
		require.Equal(t, body, resp.Body, "an empty body is left as it is")
	}
}

func TestEHBPReportsAnUnauthenticatedResponseAsAnAttestationError(t *testing.T) {
	reset := errors.New("connection reset by peer")
	for name, tc := range map[string]struct {
		err      error
		category error
	}{
		"a missing nonce":     {ehbpprotocol.Errorf(ehbpprotocol.MissingResponseNonce, "missing"), errs.ErrAttestation},
		"an invalid nonce":    {ehbpprotocol.Errorf(ehbpprotocol.InvalidResponseNonce, "invalid"), errs.ErrAttestation},
		"a duplicate nonce":   {ehbpprotocol.Errorf(ehbpprotocol.DuplicateResponseNonce, "duplicate"), errs.ErrAttestation},
		"a forged chunk":      {ehbpprotocol.Errorf(ehbpprotocol.AEADDecryptFailed, "failed to decrypt chunk"), errs.ErrAttestation},
		"an oversized chunk":  {ehbpprotocol.Errorf(ehbpprotocol.ChunkTooLarge, "too large"), errs.ErrAttestation},
		"a sequence overflow": {ehbpprotocol.Errorf(ehbpprotocol.SequenceOverflow, "overflow"), errs.ErrAttestation},
		"a truncated body":    {ehbpprotocol.Errorf(ehbpprotocol.FramingTruncated, "failed to read chunk length: %w", reset), nil},
		"a reset":             {reset, nil},
	} {
		t.Run(name, func(t *testing.T) {
			sealing := &ehbpRoundTripper{sealing: roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, tc.err })}
			_, err := sealing.RoundTrip(newRequest(t, http.MethodPost, "https://enclave.example/", strings.NewReader("{}")))
			require.ErrorIs(t, err, tc.err)
			if tc.category != nil {
				testutil.RequireCategory(t, err, tc.category)
			} else {
				require.NotErrorIs(t, err, errs.ErrAttestation, "left for the backstop")
			}

			sealing = &ehbpRoundTripper{sealing: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: &failingBody{data: strings.NewReader(""), err: tc.err}}, nil
			})}
			resp, err := sealing.RoundTrip(newRequest(t, http.MethodPost, "https://enclave.example/", strings.NewReader("{}")))
			require.NoError(t, err)
			_, err = io.ReadAll(resp.Body)
			require.ErrorIs(t, err, tc.err)
			if tc.category != nil {
				testutil.RequireCategory(t, err, tc.category)
			} else {
				require.NotErrorIs(t, err, errs.ErrAttestation)
			}
		})
	}
}
