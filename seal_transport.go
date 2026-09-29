package tinfoil

import (
	"bytes"
	"cmp"
	"crypto/hkdf"
	"crypto/hmac"
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
	"mime/multipart"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/tinfoilsh/tinfoil-go/verifier"
	"github.com/tinfoilsh/tinfoil-go/verifier/client"
)

const (
	modelHeader          = "X-Tinfoil-Model"
	cachePrefixHeader    = "X-Tinfoil-Cache-Prefix"
	sealHeader           = "X-Tinfoil-Seal"
	maxSealRedirects     = 3
	maxRerouted          = 1024
	maxMultipartBodySize = 64 << 20

	catalogPath         = "/catalog"
	catalogFetchTimeout = 10 * time.Second
	trustedRepoOwner    = "tinfoilsh/"

	// Derived client-side: no router sits between a gateway client and the engine.
	cacheSaltField = "cache_salt"
	// Separates the salt from the secret's other use, the cache-prefix hash.
	cacheSaltDomainTag  = "tinfoil/client-cache-salt/v2"
	cacheRouteDomainTag = "tinfoil/client-cache-route/v2"
)

type CatalogEntry struct {
	Repo  string   `json:"repo"`
	Hosts []string `json:"hosts"`
}

// Catalog maps model names to untrusted repository and replica entries.
type Catalog map[string]CatalogEntry

// FetchCatalog reads the catalog of the gateway at host, keeping only models
// with replicas of a bare tinfoilsh/ repository, without a tag or digest.
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
	repo, tag, digest, err := verifier.ParseReference(e.Repo)
	return err == nil && tag == "" && digest == "" && strings.HasPrefix(repo, trustedRepoOwner) && len(e.Hosts) > 0
}

// Gateway is an OpenAI client that seals each request to a verified replica
// of the model it names.
type Gateway struct {
	*openai.Client
	httpClient *http.Client
	seal       *sealTransport
}

type GatewayOptions struct {
	// Routing overrides and non-EHBP transports are rejected.
	ClientOptions []ClientOption
	ModelPins     map[string]ModelPin
	// Requires at least one pin.
	PinnedModelsOnly bool
}

// ModelPin pins a model to tinfoilsh/name[@tag][@sha256:digest].
// Nil Verification inherits gateway defaults; non-nil replaces them.
// Zero FreshnessMaxAge in a replacement uses the SDK's seven-day default.
type ModelPin struct {
	Repo         string
	Verification *client.VerificationOptions
}

// NewGateway copies opts and reads catalog on every request; nil fetches it once.
// Catalog callbacks must return immutable maps safe for concurrent readers.
// Replicas are verified on first use.
func NewGateway(baseURL string, catalog func() Catalog, opts GatewayOptions) (*Gateway, error) {
	cfg := &clientConfig{}
	for _, opt := range opts.ClientOptions {
		if opt != nil {
			opt(cfg)
		}
	}
	base, err := url.Parse(baseURL)
	if err != nil || base.Scheme != "https" || base.Host == "" {
		return nil, &ConfigurationError{Err: fmt.Errorf("gateway base URL must be an absolute HTTPS URL: %q", baseURL)}
	}
	if cfg.enclave != "" || cfg.repo != "" || cfg.baseURLSet || cmp.Or(cfg.transport, TransportEHBP) != TransportEHBP {
		return nil, &ConfigurationError{Err: fmt.Errorf("gateway client options cannot set an enclave, repository, base URL, or non-EHBP transport")}
	}
	policy, err := newGatewayPolicy(opts, cfg.verification)
	if err != nil {
		return nil, &ConfigurationError{Err: err}
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
		policy:  policy,
		secret:  resolveUserCacheSecret(cfg.userCacheSecret, cfg.userCacheSecretSet),
		build: func(r replica) (http.RoundTripper, error) {
			verification := policy.defaults
			if pin, pinned := policy.pins[r.model]; pinned {
				verification = pin.verification
			}
			secure, err := client.NewSecureClient(r.host, r.ref, &verification)
			if err != nil {
				return nil, err
			}
			httpClient, err := ehbpHTTPClient(secure.ViaRelay(base.Host), baseURL)
			if err != nil {
				return nil, err
			}
			return &recoveryTransport{transport: httpClient.Transport}, nil
		},
	}
	httpClient, err := boundHTTPClient(&http.Client{Transport: seal}, "", baseURL, "")
	if err != nil {
		return nil, err
	}
	openaiClient := openai.NewClient(append(cfg.openaiOpts, option.WithHTTPClient(httpClient), option.WithBaseURL(baseURL))...)
	return &Gateway{Client: &openaiClient, httpClient: httpClient, seal: seal}, nil
}

// HTTPClient seals requests to a replica of the model named in their body.
func (g *Gateway) HTTPClient() *http.Client {
	return g.httpClient
}

// Serves checks the current catalog against the gateway policy without verifying replicas.
func (g *Gateway) Serves(model string) bool {
	_, _, err := g.seal.policy.resolve(model, g.seal.catalog())
	return err == nil
}

type modelPolicy struct {
	repo, ref    string
	verification client.VerificationOptions
}

type gatewayPolicy struct {
	pins       map[string]modelPolicy
	pinnedOnly bool
	defaults   client.VerificationOptions
}

func newGatewayPolicy(opts GatewayOptions, defaults client.VerificationOptions) (gatewayPolicy, error) {
	if opts.PinnedModelsOnly && len(opts.ModelPins) == 0 {
		return gatewayPolicy{}, fmt.Errorf("pinned-only mode requires at least one model pin")
	}
	defaults, err := snapshotVerificationOptions(defaults)
	if err != nil {
		return gatewayPolicy{}, fmt.Errorf("gateway verification options: %w", err)
	}
	p := gatewayPolicy{pins: make(map[string]modelPolicy), pinnedOnly: opts.PinnedModelsOnly, defaults: defaults}
	for model, pin := range opts.ModelPins {
		if strings.TrimSpace(model) == "" {
			return gatewayPolicy{}, fmt.Errorf("model pin name must not be empty")
		}
		repo, _, _, err := verifier.ParseReference(pin.Repo)
		if err != nil {
			return gatewayPolicy{}, fmt.Errorf("model %q: %w", model, err)
		}
		if !strings.HasPrefix(repo, trustedRepoOwner) {
			return gatewayPolicy{}, fmt.Errorf("model %q repository %q must belong to %s", model, repo, trustedRepoOwner)
		}
		verification := defaults
		if pin.Verification != nil {
			verification, err = snapshotVerificationOptions(*pin.Verification)
			if err != nil {
				return gatewayPolicy{}, fmt.Errorf("model %q: %w", model, err)
			}
		}
		p.pins[model] = modelPolicy{repo: repo, ref: pin.Repo, verification: verification}
	}
	return p, nil
}

func snapshotVerificationOptions(opts client.VerificationOptions) (client.VerificationOptions, error) {
	v, err := verifier.New(
		verifier.WithPinnedRegisters(opts.PinnedRegisters),
		verifier.WithFreshnessMaxAge(opts.FreshnessMaxAge),
	)
	if err != nil {
		return client.VerificationOptions{}, err
	}
	return client.VerificationOptions{
		PinnedRegisters: v.PinnedRegisters(),
		FreshnessMaxAge: v.FreshnessMaxAge(),
	}, nil
}

func (p *gatewayPolicy) resolve(model string, catalog Catalog) ([]string, replica, error) {
	pin, pinned := p.pins[model]
	if p.pinnedOnly && !pinned {
		return nil, replica{}, &ConfigurationError{Err: fmt.Errorf("model %q is not pinned", model)}
	}
	entry := catalog[model]
	if !entry.trusted() {
		return nil, replica{}, &ConfigurationError{Err: fmt.Errorf("model %q has no valid bare %s repository with replicas in the gateway catalog", model, trustedRepoOwner)}
	}
	if pinned {
		if entry.Repo != pin.repo {
			return nil, replica{}, &AttestationError{Err: fmt.Errorf("model %q: expected repository %q, gateway offered %q", model, pin.repo, entry.Repo)}
		}
		return entry.Hosts, replica{ref: pin.ref, model: model}, nil
	}
	return entry.Hosts, replica{ref: entry.Repo}, nil
}

type replica struct{ host, ref, model string }

// Cache prefixes keep conversations on the same replica across requests.
type sealTransport struct {
	build    func(replica) (http.RoundTripper, error)
	catalog  func() Catalog
	policy   gatewayPolicy
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
	hosts, r, err := t.policy.resolve(model, t.catalog())
	if err != nil {
		closeRequestBody(req)
		return nil, err
	}
	hasBody := req.Body != nil && req.Body != http.NoBody
	replayable := !hasBody || req.GetBody != nil
	var transport http.RoundTripper
	prefix := req.Header.Get(cachePrefixHeader)
	for _, r.host = range rank(hosts, prefix, t.reroutedHost(prefix)) {
		if transport, err = t.enclave(r); err == nil {
			break
		}
	}
	if err != nil {
		closeRequestBody(req)
		return nil, err
	}
	for redirects := 0; ; redirects++ {
		out := req.Clone(req.Context())
		out.Header.Set(sealHeader, r.host)
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
		if resp.StatusCode != http.StatusPreconditionFailed || routed == "" || routed == r.host || !replayable {
			return resp, nil
		}
		resp.Body.Close()
		if redirects == maxSealRedirects {
			return nil, &FetchError{Err: fmt.Errorf("gateway kept routing away from the enclave the request was sealed to (last: %s)", routed)}
		}
		r.host = routed
		if transport, err = t.enclave(r); err != nil {
			return nil, fmt.Errorf("following gateway route to enclave %s: %w", routed, err)
		}
		t.remember(prefix, routed)
	}
}

func (t *sealTransport) prepare(req *http.Request) error {
	if req.Method != http.MethodPost || req.Body == nil || req.Body == http.NoBody {
		return nil
	}
	mediaType, params, err := mime.ParseMediaType(req.Header.Get("Content-Type"))
	if err != nil {
		return nil
	}
	if mediaType == "multipart/form-data" {
		// Explicit routing keeps uploads streaming; callers provide GetBody for retries.
		if req.Header.Get(modelHeader) != "" {
			return nil
		}
		return prepareMultipart(req, params["boundary"])
	}
	if mediaType != "application/json" {
		return nil
	}
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
			body, err = t.scopeCache(req.Header, fields, body)
			if err != nil {
				return err
			}
		}
	}
	setGatewayBody(req, body)
	return nil
}

func setGatewayBody(req *http.Request, body []byte) {
	req.ContentLength = int64(len(body))
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}
	req.Body, _ = req.GetBody()
}

func prepareMultipart(req *http.Request, boundary string) error {
	defer req.Body.Close()
	if boundary == "" {
		return &ConfigurationError{Err: fmt.Errorf("multipart upload is missing its boundary")}
	}
	body, err := io.ReadAll(http.MaxBytesReader(nil, req.Body, maxMultipartBodySize))
	if err != nil {
		return fmt.Errorf("reading multipart upload: %w", err)
	}
	reader := multipart.NewReader(bytes.NewReader(body), boundary)
	var model string
	for {
		part, err := reader.NextRawPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return &ConfigurationError{Err: fmt.Errorf("invalid multipart upload: %w", err)}
		}
		if part.FormName() == "model" {
			if model != "" || part.FileName() != "" {
				return &ConfigurationError{Err: fmt.Errorf("multipart upload must contain exactly one model field, not a file")}
			}
			value, err := io.ReadAll(part)
			if err != nil {
				return &ConfigurationError{Err: fmt.Errorf("reading multipart model: %w", err)}
			}
			model = string(value)
			if strings.TrimSpace(model) == "" {
				return &ConfigurationError{Err: fmt.Errorf("multipart model must not be empty")}
			}
		} else if _, err := io.Copy(io.Discard, part); err != nil {
			return &ConfigurationError{Err: fmt.Errorf("reading multipart field: %w", err)}
		}
	}
	if model == "" {
		return &ConfigurationError{Err: fmt.Errorf("multipart upload is missing its model field")}
	}
	req.Header.Set(modelHeader, model)
	setGatewayBody(req, body)
	return nil
}

// The engine only needs the salt; the secret itself never leaves the client.
func (t *sealTransport) scopeCache(h http.Header, fields map[string]json.RawMessage, body []byte) ([]byte, error) {
	var secret string
	json.Unmarshal(fields[userCacheSecretField], &secret)
	if secret = cmp.Or(secret, t.secret); secret == "" {
		return body, nil
	}
	scheme, apiKey, _ := strings.Cut(h.Get("Authorization"), " ")
	if !strings.EqualFold(scheme, "Bearer") {
		apiKey = ""
	}
	apiKey = strings.TrimSpace(apiKey)
	salt, err := deriveCacheSalt(secret, apiKey)
	if err != nil {
		return nil, err
	}
	h.Del(cachePrefixHeader)
	if head := promptHead(fields); head != nil {
		key, err := hkdf.Key(sha256.New, []byte(secret), []byte(apiKey), cacheRouteDomainTag, sha256.Size)
		if err != nil {
			return nil, fmt.Errorf("deriving cache routing key: %w", err)
		}
		mac := hmac.New(sha256.New, key)
		mac.Write(head)
		h.Set(cachePrefixHeader, hex.EncodeToString(mac.Sum(nil)))
	}
	delete(fields, userCacheSecretField)
	fields[cacheSaltField], _ = json.Marshal(salt)
	return json.Marshal(fields)
}

func deriveCacheSalt(secret, apiKey string) (string, error) {
	key, err := hkdf.Key(sha256.New, []byte(secret), []byte(apiKey), cacheSaltDomainTag, sha256.Size)
	if err != nil {
		return "", fmt.Errorf("deriving cache salt: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(key), nil
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
