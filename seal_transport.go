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
	"math/rand/v2"
	"mime"
	"mime/multipart"
	"net/http"
	"slices"
	"strings"
	"sync"

	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/client"
)

const (
	modelHeader          = "X-Tinfoil-Model"
	cachePrefixHeader    = "X-Tinfoil-Cache-Prefix"
	sealHeader           = "X-Tinfoil-Seal"
	maxSealRedirects     = 3
	maxRerouted          = 1024
	maxMultipartBodySize = 64 << 20

	// Derived client-side: no router sits between a gateway client and the engine.
	cacheSaltField = "cache_salt"
	// Derives both the salt and the cache-prefix key from the secret.
	cacheSaltDomainTag = "tinfoil/client-cache-salt/v2"
)

type gatewayPolicy struct {
	pins       map[string]*client.SecureClient
	pinnedOnly bool
	defaults   client.VerificationOptions
}

func newGatewayPolicy(opts GatewayOptions, defaults client.VerificationOptions) (gatewayPolicy, error) {
	if opts.PinnedModelsOnly && len(opts.ModelPins) == 0 {
		return gatewayPolicy{}, fmt.Errorf("pinned-only mode requires at least one model pin")
	}
	v, err := verify.New(verify.WithPinnedRegisters(defaults.PinnedRegisters), verify.WithFreshnessMaxAge(defaults.FreshnessMaxAge))
	if err != nil {
		return gatewayPolicy{}, fmt.Errorf("gateway verification options: %w", err)
	}
	p := gatewayPolicy{
		pins:       make(map[string]*client.SecureClient),
		pinnedOnly: opts.PinnedModelsOnly,
		defaults:   client.VerificationOptions{PinnedRegisters: v.PinnedRegisters(), FreshnessMaxAge: v.FreshnessMaxAge()},
	}
	for model, pin := range opts.ModelPins {
		if strings.TrimSpace(model) == "" || !strings.HasPrefix(pin.Repo, trustedRepoOwner) {
			return gatewayPolicy{}, fmt.Errorf("model pin %q repository %q must belong to %s", model, pin.Repo, trustedRepoOwner)
		}
		secure, err := client.NewSecureClient("", pin.Repo, cmp.Or(pin.Verification, &p.defaults))
		if err != nil {
			return gatewayPolicy{}, fmt.Errorf("model %q: %w", model, err)
		}
		p.pins[model] = secure
	}
	return p, nil
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
		if repo, _, _ := strings.Cut(pin.Repo(), "@"); entry.Repo != repo {
			return nil, replica{}, &AttestationError{Err: fmt.Errorf("model %q: expected repository %q, gateway offered %q", model, repo, entry.Repo)}
		}
		return entry.Hosts, replica{ref: pin.Repo(), model: model}, nil
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
	form, err := multipart.NewReader(bytes.NewReader(body), boundary).ReadForm(maxMultipartBodySize)
	if err != nil {
		return &ConfigurationError{Err: fmt.Errorf("invalid multipart upload: %w", err)}
	}
	defer form.RemoveAll()
	models := form.Value["model"]
	if len(models) != 1 || strings.TrimSpace(models[0]) == "" || form.File["model"] != nil {
		return &ConfigurationError{Err: fmt.Errorf("multipart upload must contain exactly one non-empty model field")}
	}
	req.Header.Set(modelHeader, models[0])
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
	key, err := hkdf.Key(sha256.New, []byte(secret), []byte(h.Get("Authorization")), cacheSaltDomainTag, 2*sha256.Size)
	if err != nil {
		return nil, fmt.Errorf("deriving cache keys: %w", err)
	}
	h.Del(cachePrefixHeader)
	if head := promptHead(fields); head != nil {
		mac := hmac.New(sha256.New, key[sha256.Size:])
		mac.Write(head)
		h.Set(cachePrefixHeader, hex.EncodeToString(mac.Sum(nil)))
	}
	delete(fields, userCacheSecretField)
	fields[cacheSaltField], _ = json.Marshal(base64.RawURLEncoding.EncodeToString(key[:sha256.Size]))
	return json.Marshal(fields)
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
