package tinfoil

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"slices"
	"sync"

	"github.com/tinfoilsh/tinfoil-go/verifier/client"
)

const (
	modelHeader       = "X-Tinfoil-Model"
	cachePrefixHeader = "X-Tinfoil-Cache-Prefix"
	sealHeader        = "X-Tinfoil-Seal"
	maxSealRedirects  = 3
)

type sealedEnclave struct {
	secure    *client.SecureClient
	transport http.RoundTripper
}

type sealTransport struct {
	build    func(*client.SecureClient) (http.RoundTripper, error)
	mu       sync.Mutex
	active   *sealedEnclave
	enclaves map[string]*sealedEnclave
}

func newSealTransport(secure *client.SecureClient, build func(*client.SecureClient) (http.RoundTripper, error)) (*sealTransport, error) {
	t := &sealTransport{build: build, enclaves: map[string]*sealedEnclave{}}
	if _, err := t.follow(secure); err != nil {
		return nil, err
	}
	return t, nil
}

func (t *sealTransport) enclave() *client.SecureClient {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.active.secure
}

func (t *sealTransport) follow(secure *client.SecureClient) (*sealedEnclave, error) {
	t.mu.Lock()
	e := t.enclaves[secure.Enclave()]
	t.mu.Unlock()
	if e == nil || e.secure.Enclave() != secure.Enclave() {
		transport, err := t.build(secure)
		if err != nil {
			return nil, err
		}
		e = &sealedEnclave{secure: secure, transport: transport}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.enclaves[secure.Enclave()] = e
	t.active = e
	return e, nil
}

func (t *sealTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	if err := prepareRoutingHeaders(req); err != nil {
		return nil, err
	}
	hasBody := req.Body != nil && req.Body != http.NoBody
	replayable := !hasBody || req.GetBody != nil
	t.mu.Lock()
	e := t.active
	t.mu.Unlock()
	for redirects := 0; ; redirects++ {
		out := req.Clone(req.Context())
		out.Header.Set(sealHeader, e.secure.Enclave())
		if redirects > 0 && hasBody {
			var err error
			out.Body, err = req.GetBody()
			if err != nil {
				return nil, fmt.Errorf("replaying request after enclave reroute: %w", err)
			}
		}
		resp, err := e.transport.RoundTrip(out)
		if err != nil {
			return nil, err
		}
		routed := resp.Header.Get(sealHeader)
		if resp.StatusCode != http.StatusPreconditionFailed || routed == "" || routed == e.secure.Enclave() || !replayable {
			return resp, nil
		}
		resp.Body.Close()
		if redirects == maxSealRedirects {
			return nil, &FetchError{Err: fmt.Errorf("gateway kept routing away from the enclave the request was sealed to (last: %s)", routed)}
		}
		if e, err = t.follow(e.secure.ForEnclave(routed)); err != nil {
			return nil, fmt.Errorf("following gateway route to enclave %s: %w", routed, err)
		}
	}
}

func prepareRoutingHeaders(req *http.Request) error {
	if req.Method != http.MethodPost || req.Body == nil || req.Body == http.NoBody {
		return nil
	}
	mediaType, _, err := mime.ParseMediaType(req.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return nil
	}
	// Only inspect JSON inference requests. Uploads keep their original body
	// and use GetBody if a seal mismatch requires another attempt.
	body, err := io.ReadAll(req.Body)
	req.Body.Close()
	if err != nil {
		return err
	}
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}
	req.Body, _ = req.GetBody()
	setRoutingHeaders(req.Header, body)
	return nil
}

func setRoutingHeaders(h http.Header, body []byte) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil {
		return
	}
	var model string
	if h.Get(modelHeader) == "" && json.Unmarshal(fields["model"], &model) == nil && model != "" {
		h.Set(modelHeader, model)
	}
	var secret string
	if h.Get(cachePrefixHeader) != "" || json.Unmarshal(fields[userCacheSecretField], &secret) != nil || secret == "" {
		return
	}
	if head := promptHead(fields); head != nil {
		sum := sha256.Sum256(slices.Concat([]byte(secret), []byte{0}, head))
		h.Set(cachePrefixHeader, hex.EncodeToString(sum[:]))
	}
}

// The first element is the prefix later turns of a conversation share.
func promptHead(fields map[string]json.RawMessage) json.RawMessage {
	var instructions string
	if json.Unmarshal(fields["instructions"], &instructions) == nil && instructions != "" {
		return fields["instructions"]
	}
	for _, name := range []string{"messages", "input", "prompt"} {
		raw, ok := fields[name]
		if !ok || bytes.Equal(raw, []byte("null")) {
			continue
		}
		var items []json.RawMessage
		if json.Unmarshal(raw, &items) != nil {
			return raw
		}
		if len(items) > 0 {
			return items[0]
		}
	}
	return nil
}
