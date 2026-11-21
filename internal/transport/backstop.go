package transport

import (
	"context"
	"io"
	"net/http"

	"github.com/tinfoilsh/tinfoil-go/internal/errs"
)

// WithBackstop returns next behind the error backstop of a client's request
// path, which each route installs outermost. It applies errs.Finish, under
// the request's context, to the error of each request and to the errors that
// reading or closing its response body returns, such as a reset in the
// middle of a stream or a body that fails to decrypt. So an error that no
// layer below classified, such as a refused connection, becomes a network
// error, while an SDK error and the cancellation of the request's context
// pass through as they are.
func WithBackstop(next http.RoundTripper) http.RoundTripper {
	return &backstopTransport{transport: next}
}

type backstopTransport struct {
	transport http.RoundTripper
}

func (t *backstopTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	resp, err := t.transport.RoundTrip(req)
	if err != nil {
		return resp, errs.Finish(ctx, err)
	}
	if resp != nil && resp.Body != nil && resp.Body != http.NoBody {
		resp.Body = backstopBody(ctx, resp.Body)
	}
	return resp, nil
}

func (t *backstopTransport) CloseIdleConnections() {
	closeIdleConnections(t.transport)
}

// backstopBody returns body with errs.Finish applied to its errors. The body
// of a protocol switch, such as a WebSocket upgrade, is also an io.Writer,
// which net/http's callers expect, so the result keeps it one.
func backstopBody(ctx context.Context, body io.ReadCloser) io.ReadCloser {
	b := &finishingBody{ctx: ctx, body: body}
	if w, ok := body.(io.ReadWriteCloser); ok {
		return &finishingReadWriteBody{finishingBody: b, writer: w}
	}
	return b
}

type finishingBody struct {
	ctx  context.Context
	body io.ReadCloser
}

func (b *finishingBody) Read(p []byte) (int, error) {
	n, err := b.body.Read(p)
	// io.EOF is the end of the body, not a failure, and readers compare it
	// with ==.
	if err != nil && err != io.EOF {
		err = errs.Finish(b.ctx, err)
	}
	return n, err
}

func (b *finishingBody) Close() error {
	return errs.Finish(b.ctx, b.body.Close())
}

type finishingReadWriteBody struct {
	*finishingBody
	writer io.Writer
}

func (b *finishingReadWriteBody) Write(p []byte) (int, error) {
	n, err := b.writer.Write(p)
	return n, errs.Finish(b.ctx, err)
}
