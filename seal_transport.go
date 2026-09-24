package tinfoil

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"math/rand/v2"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/tinfoilsh/tinfoil-go/verifier/client"
)

const (
	modelHeader       = "X-Tinfoil-Model"
	cachePrefixHeader = "X-Tinfoil-Cache-Prefix"
	sealHeader        = "X-Tinfoil-Seal"
	maxSealRedirects  = 3
	maxRerouted       = 1024

	catalogPath         = "/catalog"
	catalogFetchTimeout = 10 * time.Second
	trustedRepoOwner    = "tinfoilsh/"

	// Derived client-side: no router sits between a gateway client and the engine.
	cacheSaltField = "cache_salt"
	// Separates the salt from the secret's other use, the cache-prefix hash.
	cacheSaltDomainTag = "tinfoil/client-cache-salt/v1"
)

// CatalogEntry lists a model's repository and replica hosts.
type CatalogEntry struct {
	Repo  string   `json:"repo"`
	Hosts []string `json:"hosts"`
}

// Catalog maps model names to their entries. It is untrusted: each replica is
// verified against its repository before anything is sealed to it.
type Catalog map[string]CatalogEntry

// FetchCatalog reads the catalog of the gateway at host, keeping only models
// with replicas of a tinfoilsh/ repository.
func FetchCatalog(host string) (Catalog, error) {
	resp, err := (&http.Client{Timeout: catalogFetchTimeout}).Get("https://" + host + catalogPath)
	if err != nil {
		return nil, &FetchError{Err: err}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &FetchError{Err: fmt.Errorf("fetching gateway catalog: %s", resp.Status)}
	}
	var catalog Catalog
	if err := json.NewDecoder(resp.Body).Decode(&catalog); err != nil {
		return nil, &FetchError{Err: fmt.Errorf("decoding gateway catalog: %w", err)}
	}
	maps.DeleteFunc(catalog, func(_ string, entry CatalogEntry) bool { return !entry.trusted() })
	return catalog, nil
}

func (e CatalogEntry) trusted() bool {
	return strings.HasPrefix(e.Repo, trustedRepoOwner) && len(e.Hosts) > 0
}

// Gateway is an OpenAI client that seals each request to a verified replica
// of the model it names.
type Gateway struct {
	*openai.Client
	httpClient *http.Client
}

// NewGateway reads catalog on every request, so a long-running caller can
// refresh it; nil fetches it once. It accepts WithVerificationOptions,
// WithUserCacheSecret and WithOpenAIOptions.
func NewGateway(baseURL string, catalog func() Catalog, opts ...ClientOption) (*Gateway, error) {
	cfg := &clientConfig{}
	for _, opt := range opts {
		if opt != nil {
			opt(cfg)
		}
	}
	if cfg.enclave != "" || cfg.repo != "" || cmp.Or(cfg.transport, TransportEHBP) != TransportEHBP || cfg.baseURLSet {
		return nil, &ConfigurationError{Err: fmt.Errorf("a gateway takes its enclaves and repositories from its catalog and uses the EHBP transport")}
	}
	base, err := url.Parse(baseURL)
	if err != nil || base.Scheme != "https" || base.Host == "" {
		return nil, &ConfigurationError{Err: fmt.Errorf("gateway base URL must be an absolute HTTPS URL: %q", baseURL)}
	}
	if catalog == nil {
		fetched, err := FetchCatalog(base.Host)
		if err != nil {
			return nil, err
		}
		catalog = func() Catalog { return fetched }
	}
	seal := &sealTransport{
		catalog: catalog,
		secret:  resolveUserCacheSecret(cfg.userCacheSecret, cfg.userCacheSecretSet),
		build: func(r replica) (http.RoundTripper, error) {
			secure, err := client.NewSecureClient(r.host, r.repo, &cfg.verification)
			if err != nil {
				return nil, err
			}
			httpClient, err := ehbpHTTPClient(secure.ViaRelay(base.Host), baseURL)
			if err != nil {
				return nil, err
			}
			return httpClient.Transport, nil
		},
	}
	httpClient, err := boundHTTPClient(&http.Client{Transport: seal}, "", baseURL, "")
	if err != nil {
		return nil, err
	}
	openaiClient := openai.NewClient(append(cfg.openaiOpts, option.WithHTTPClient(httpClient), option.WithBaseURL(baseURL))...)
	return &Gateway{Client: &openaiClient, httpClient: httpClient}, nil
}

// HTTPClient seals requests to a replica of the model named in their body.
func (g *Gateway) HTTPClient() *http.Client {
	return g.httpClient
}

type replica struct{ host, repo string }

// sealTransport picks each request's replica from its cache prefix, or from
// where the gateway last rerouted that prefix, so a conversation stays on one
// warm replica.
type sealTransport struct {
	build    func(replica) (http.RoundTripper, error)
	catalog  func() Catalog
	secret   string
	enclaves sync.Map // replica to http.RoundTripper
	mu       sync.Mutex
	rerouted map[string]string // cache prefix to host
}

func (t *sealTransport) enclave(r replica) (http.RoundTripper, error) {
	if rt, ok := t.enclaves.Load(r); ok {
		return rt.(http.RoundTripper), nil
	}
	rt, err := t.build(r)
	if err != nil {
		return nil, err
	}
	t.enclaves.Store(r, rt)
	return rt, nil
}

func (t *sealTransport) reroutedHost(prefix string) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.rerouted[prefix]
}

func (t *sealTransport) remember(prefix, host string) {
	if prefix == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.rerouted == nil || len(t.rerouted) == maxRerouted {
		t.rerouted = map[string]string{}
	}
	t.rerouted[prefix] = host
}

// rank orders hosts by rendezvous score for a cache prefix, or randomly without one.
func rank(hosts []string, prefix, first string) []string {
	hosts = slices.Clone(hosts)
	if prefix == "" {
		rand.Shuffle(len(hosts), func(i, j int) { hosts[i], hosts[j] = hosts[j], hosts[i] })
		return hosts
	}
	score := func(host string) uint64 {
		sum := sha256.Sum256([]byte(prefix + "\x00" + host))
		return binary.BigEndian.Uint64(sum[:])
	}
	slices.SortFunc(hosts, func(a, b string) int { return cmp.Compare(score(b), score(a)) })
	if i := slices.Index(hosts, first); i > 0 {
		copy(hosts[1:i+1], hosts[:i])
		hosts[0] = first
	}
	return hosts
}

func (t *sealTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	if err := t.prepare(req); err != nil {
		return nil, err
	}
	model := req.Header.Get(modelHeader)
	entry := t.catalog()[model]
	if !entry.trusted() {
		return nil, &ConfigurationError{Err: fmt.Errorf("model %q has no %s replicas in the gateway catalog", model, trustedRepoOwner)}
	}
	hasBody := req.Body != nil && req.Body != http.NoBody
	replayable := !hasBody || req.GetBody != nil
	var host string
	var transport http.RoundTripper
	var err error
	prefix := req.Header.Get(cachePrefixHeader)
	for _, host = range rank(entry.Hosts, prefix, t.reroutedHost(prefix)) {
		if transport, err = t.enclave(replica{host, entry.Repo}); err == nil {
			break
		}
	}
	if err != nil {
		return nil, err
	}
	for redirects := 0; ; redirects++ {
		out := req.Clone(req.Context())
		out.Header.Set(sealHeader, host)
		if redirects > 0 && hasBody {
			var err error
			out.Body, err = req.GetBody()
			if err != nil {
				return nil, fmt.Errorf("replaying request after enclave reroute: %w", err)
			}
		}
		resp, err := transport.RoundTrip(out)
		if err != nil {
			return nil, err
		}
		routed := resp.Header.Get(sealHeader)
		if resp.StatusCode != http.StatusPreconditionFailed || routed == "" || routed == host || !replayable {
			return resp, nil
		}
		resp.Body.Close()
		if redirects == maxSealRedirects {
			return nil, &FetchError{Err: fmt.Errorf("gateway kept routing away from the enclave the request was sealed to (last: %s)", routed)}
		}
		if transport, err = t.enclave(replica{routed, entry.Repo}); err != nil {
			return nil, fmt.Errorf("following gateway route to enclave %s: %w", routed, err)
		}
		t.remember(prefix, routed)
		host = routed
	}
}

func (t *sealTransport) prepare(req *http.Request) error {
	if req.Method != http.MethodPost || req.Body == nil || req.Body == http.NoBody {
		return nil
	}
	mediaType, _, err := mime.ParseMediaType(req.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return nil
	}
	// Only inspect JSON inference requests. Uploads keep their original body
	// and use GetBody if a seal mismatch requires another attempt.
	scoped := userCacheSecretPathEligible(req)
	body, err := io.ReadAll(req.Body)
	req.Body.Close()
	if err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) == nil && fields != nil {
		var model string
		if req.Header.Get(modelHeader) == "" && json.Unmarshal(fields["model"], &model) == nil && model != "" {
			req.Header.Set(modelHeader, model)
		}
		if scoped {
			body = t.scopeCache(req.Header, fields, body)
		}
	}
	req.ContentLength = int64(len(body))
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}
	req.Body, _ = req.GetBody()
	return nil
}

// The engine only needs the salt; the secret itself never leaves the client.
func (t *sealTransport) scopeCache(h http.Header, fields map[string]json.RawMessage, body []byte) []byte {
	var secret string
	json.Unmarshal(fields[userCacheSecretField], &secret)
	if secret = cmp.Or(secret, t.secret); secret == "" {
		return body
	}
	if head := promptHead(fields); head != nil && h.Get(cachePrefixHeader) == "" {
		sum := sha256.Sum256(slices.Concat([]byte(secret), []byte{0}, head))
		h.Set(cachePrefixHeader, hex.EncodeToString(sum[:]))
	}
	delete(fields, userCacheSecretField)
	fields[cacheSaltField], _ = json.Marshal(deriveCacheSalt(secret))
	if scoped, err := json.Marshal(fields); err == nil {
		return scoped
	}
	return body
}

func deriveCacheSalt(secret string) string {
	sum := sha256.Sum256([]byte(cacheSaltDomainTag + "\x00" + secret))
	return base64.RawURLEncoding.EncodeToString(sum[:])
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
