package gateway

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/internal/errs"
	"github.com/tinfoilsh/tinfoil-go/internal/testutil"
)

// An upload over the limit is the caller's mistake, while a failure to read
// it is left for the client's backstop.
func TestSealClassifiesAnUploadThatCantBeRead(t *testing.T) {
	seal := sealTestTransport(func(string) (http.RoundTripper, error) {
		t.Error("an upload that can't be read is never sent")
		return nil, errors.New("unreachable")
	})
	upload := func(body io.Reader) *http.Request {
		req, err := http.NewRequest(http.MethodPost, "https://gateway.example/v1/audio/transcriptions", body)
		require.NoError(t, err)
		req.Header.Set("Content-Type", "multipart/form-data; boundary=test")
		return req
	}
	_, err := seal.RoundTrip(upload(io.LimitReader(zeros{}, maxMultipartBodySize+1)))
	testutil.RequireCategory(t, err, errs.ErrConfiguration)
	require.ErrorContains(t, err, "multipart upload exceeds")

	reset := errors.New("connection reset by peer")
	_, err = seal.RoundTrip(upload(io.MultiReader(strings.NewReader("--test"), failingReader{reset})))
	require.ErrorIs(t, err, reset)
	testutil.RequireCategory(t, errs.Finish(t.Context(), err), errs.ErrNetwork)
	for _, category := range []error{errs.ErrConfiguration, errs.ErrNetwork, errs.ErrAttestation} {
		require.NotErrorIs(t, err, category, "left for the backstop")
	}
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

type failingReader struct{ err error }

func (r failingReader) Read([]byte) (int, error) { return 0, r.err }
