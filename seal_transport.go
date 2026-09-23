package tinfoil

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"mime"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/tinfoilsh/tinfoil-go/verifier/client"
	"github.com/tinfoilsh/tinfoil-go/verifier/util"
)

const (
	modelHeader       = "X-Tinfoil-Model"
	cachePrefixHeader = "X-Tinfoil-Cache-Prefix"
	sealHeader        = "X-Tinfoil-Seal"
	maxSealRedirects  = 3

	catalogPath = "/catalog"
	catalogTTL  = 5 * time.Minute
)

type sealedEnclave struct {
	secure    *client.SecureClient
	transport http.RoundTripper
}

// sealTransport picks each request's replica from its cache prefix, so a
// conversation stays on one warm replica.
type sealTransport struct {
	build func(*client.SecureClient) (http.RoundTripper, error)
	relay string
	home  *sealedEnclave

	mu       sync.Mutex
	enclaves map[string]*sealedEnclave

	catalogMu sync.Mutex
	catalog   catalog
	fetchedAt time.Time
}

type catalog map[string]struct {
	Hosts []string `json:"hosts"`
}

func newSealTransport(secure *client.SecureClient, relay string, build func(*client.SecureClient) (http.RoundTripper, error)) (*sealTransport, error) {
	transport, err := build(secure)
	if err != nil {
		return nil, err
	}
	home := &sealedEnclave{secure: secure, transport: transport}
	return &sealTransport{
		build:    build,
		relay:    relay,
		home:     home,
		enclaves: map[string]*sealedEnclave{secure.Enclave(): home},
	}, nil
}

func (t *sealTransport) enclave(host string) (*sealedEnclave, error) {
	t.mu.Lock()
	e := t.enclaves[host]
	t.mu.Unlock()
	if e != nil {
		return e, nil
	}
	secure := t.home.secure.ForEnclave(host).ViaRelay(t.relay)
	transport, err := t.build(secure)
	if err != nil {
		return nil, err
	}
	e = &sealedEnclave{secure: secure, transport: transport}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.enclaves[host] = e
	return e, nil
}

func (t *sealTransport) pick(model, prefix string) string {
	hosts := t.replicas(model)
	if len(hosts) == 0 {
		return t.home.secure.Enclave()
	}
	if prefix == "" {
		return hosts[rand.IntN(len(hosts))]
	}
	best, bestScore := "", uint64(0)
	for _, host := range hosts {
		sum := sha256.Sum256([]byte(prefix + "\x00" + host))
		if score := binary.BigEndian.Uint64(sum[:]); best == "" || score > bestScore {
			best, bestScore = host, score
		}
	}
	return best
}

// replicas reads the relay's catalog, which is untrusted: each replica is
// verified against the pinned repository before anything is sealed to it.
func (t *sealTransport) replicas(model string) []string {
	if t.relay == "" || t.relay == t.home.secure.Enclave() {
		return nil
	}
	t.catalogMu.Lock()
	defer t.catalogMu.Unlock()
	if time.Since(t.fetchedAt) > catalogTTL {
		t.fetchedAt = time.Now()
		if body, _, err := util.Get("https://" + t.relay + catalogPath); err == nil {
			var fetched catalog
			if json.Unmarshal(body, &fetched) == nil {
				t.catalog = fetched
			}
		}
	}
	return t.catalog[model].Hosts
}

func (t *sealTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	if err := prepareRoutingHeaders(req); err != nil {
		return nil, err
	}
	hasBody := req.Body != nil && req.Body != http.NoBody
	replayable := !hasBody || req.GetBody != nil
	e := t.home
	if picked, err := t.enclave(t.pick(req.Header.Get(modelHeader), req.Header.Get(cachePrefixHeader))); err == nil {
		e = picked
	}
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
		if e, err = t.enclave(routed); err != nil {
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
