// Package gateway routes requests through Tinfoil's inference gateway, sealing
// each to a verified replica of the model it names.
package gateway

import (
	"bytes"
	"cmp"
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"mime"
	"mime/multipart"
	"net/http"
	"slices"
	"strings"
	"sync"

	"github.com/tinfoilsh/tinfoil-go/internal/enclave"
	"github.com/tinfoilsh/tinfoil-go/internal/errs"
	"github.com/tinfoilsh/tinfoil-go/internal/transport"
	"github.com/tinfoilsh/tinfoil-go/verify"
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
	pins       map[string]ModelPin
	pinnedOnly bool
	verifier   *verify.Verifier // for unpinned models
}

// errCallerAuthorizedConfig rejects a policy whose config the caller supplies
// or authorizes: gateway replicas are verified against repository pins.
var errCallerAuthorizedConfig = errors.New("caller-authorized config requires a direct enclave client")

func newGatewayPolicy(modelPins map[string]ModelPin, pinnedOnly bool, v *verify.Verifier) (gatewayPolicy, error) {
	if pinnedOnly && len(modelPins) == 0 {
		return gatewayPolicy{}, fmt.Errorf("pinned-only mode requires at least one model pin")
	}
	if v == nil {
		var err error
		if v, err = verify.NewVerifier(); err != nil {
			return gatewayPolicy{}, fmt.Errorf("gateway verification options: %w", err)
		}
	}
	if v.CallerAuthorizesConfig() {
		return gatewayPolicy{}, errCallerAuthorizedConfig
	}
	p := gatewayPolicy{pins: make(map[string]ModelPin), pinnedOnly: pinnedOnly, verifier: v}
	for model, pin := range modelPins {
		if pin.Verifier != nil && pin.Verifier.CallerAuthorizesConfig() {
			return gatewayPolicy{}, fmt.Errorf("model %q: %w", model, errCallerAuthorizedConfig)
		}
		if strings.TrimSpace(model) == "" || !strings.HasPrefix(pin.Repo, trustedRepoOwner) {
			return gatewayPolicy{}, fmt.Errorf("model pin %q repository %q must belong to %s", model, pin.Repo, trustedRepoOwner)
		}
		if _, _, _, err := verify.ParseReference(pin.Repo); err != nil {
			return gatewayPolicy{}, fmt.Errorf("model %q: %w", model, &errs.ConfigurationError{Err: err})
		}
		p.pins[model] = ModelPin{Repo: pin.Repo, Verifier: cmp.Or(pin.Verifier, v)}
	}
	return p, nil
}

func (p *gatewayPolicy) resolve(model string, catalog Catalog) ([]string, replica, error) {
	pin, pinned := p.pins[model]
	if p.pinnedOnly && !pinned {
		return nil, replica{}, &errs.ConfigurationError{Err: fmt.Errorf("model %q is not pinned", model)}
	}
	entry := catalog[model]
	if !entry.trusted() {
		return nil, replica{}, &errs.ConfigurationError{Err: fmt.Errorf("model %q has no valid bare %s repository with replicas in the gateway catalog", model, trustedRepoOwner)}
	}
	if pinned {
		if repo, _, _ := strings.Cut(pin.Repo, "@"); entry.Repo != repo {
			return nil, replica{}, &errs.AttestationError{Err: fmt.Errorf("model %q: expected repository %q, gateway offered %q", model, repo, entry.Repo)}
		}
		return entry.Hosts, replica{ref: pin.Repo, model: model}, nil
	}
	return entry.Hosts, replica{ref: entry.Repo}, nil
}

// verifierFor returns the policy a replica of r is verified under.
func (p *gatewayPolicy) verifierFor(r replica) *verify.Verifier {
	if pin, pinned := p.pins[r.model]; pinned {
		return pin.Verifier
	}
	return p.verifier
}

type replica struct{ host, ref, model string }

// ModelPin pins a model to tinfoilsh/name[@tag][@sha256:digest]. A nil
// Verifier inherits the gateway's; a non-nil one replaces it.
type ModelPin struct {
	Repo     string
	Verifier *verify.Verifier
}

// Config configures a Transport.
type Config struct {
	// BaseURL is where requests are sent, and Relay is the gateway host that
	// attestation is fetched through.
	BaseURL, Relay string
	// Catalog is read on every request; nil fetches it from Relay on first
	// use.
	Catalog          func() Catalog
	ModelPins        map[string]ModelPin
	PinnedModelsOnly bool
	// Verifier is the policy for unpinned models; nil selects the defaults.
	Verifier *verify.Verifier
	// UserCacheSecret is the explicit secret; empty resolves it from the
	// environment or the persisted file.
	UserCacheSecret string
}

// NewTransport copies the policy in c and does no network I/O: the catalog is
// fetched and replicas are verified on first use.
func NewTransport(c Config) (*Transport, error) {
	policy, err := newGatewayPolicy(c.ModelPins, c.PinnedModelsOnly, c.Verifier)
	if err != nil {
		return nil, &errs.ConfigurationError{Err: err}
	}
	catalog := func(context.Context) (Catalog, error) { return c.Catalog(), nil }
	if c.Catalog == nil {
		catalog = (&lazyCatalog{fetch: func(ctx context.Context) (Catalog, error) { return fetchCatalog(ctx, c.Relay) }}).get
	}
	return &Transport{
		catalog: catalog,
		policy:  policy,
		secret:  transport.ResolveUserCacheSecret(c.UserCacheSecret, c.UserCacheSecret != ""),
		build: func(r replica) (*verifiedReplicaTransport, error) {
			h, err := enclave.NewHandle(enclave.Config{Host: r.host, Relay: c.Relay, Repo: r.ref, Verifier: policy.verifierFor(r)})
			if err != nil {
				return nil, err
			}
			stack, err := transport.Enclave(h, enclave.EHBP, c.BaseURL)
			if err != nil {
				return nil, err
			}
			return &verifiedReplicaTransport{
				transport: stack,
				verification: func() *verify.Verification {
					if state := h.Current(); state != nil {
						return state.Verification()
					}
					return nil
				},
				ensureVerified: func(ctx context.Context) (*verify.Verification, error) {
					state, err := stack.EnsureVerified(ctx)
					if err != nil {
						return nil, err
					}
					return state.Verification(), nil
				},
			}, nil
		},
	}, nil
}

// Transport seals each request to a verified replica of the model it names.
// Cache prefixes keep conversations on the same replica across requests.
type Transport struct {
	build    func(replica) (*verifiedReplicaTransport, error)
	catalog  func(context.Context) (Catalog, error)
	policy   gatewayPolicy
	secret   string
	enclaves sync.Map // replica to *verifiedReplicaTransport
	mu       sync.Mutex
	rerouted map[string]string // cache prefix to host
}

func (t *Transport) enclave(r replica) (*verifiedReplicaTransport, error) {
	if rt, ok := t.enclaves.Load(r); ok {
		return rt.(*verifiedReplicaTransport), nil
	}
	rt, err := t.build(r)
	if err != nil {
		return nil, err
	}
	actual, _ := t.enclaves.LoadOrStore(r, rt)
	return actual.(*verifiedReplicaTransport), nil
}

// verified returns r's transport once r's replica verifies under ctx, so a
// caller can fall over to another replica before sealing anything to it.
func (t *Transport) verified(ctx context.Context, r replica) (*verifiedReplicaTransport, *verify.Verification, error) {
	rt, err := t.enclave(r)
	if err != nil {
		return nil, nil, err
	}
	verified, err := rt.ensureVerified(ctx)
	if err != nil {
		return nil, nil, err
	}
	return rt, verified, nil
}

// ReplicaVerification holds a replica's last successful verification.
type ReplicaVerification struct {
	// Host is the replica the verification is for.
	Host string
	// Request model names, not attested identities.
	Models       []string
	Reference    string
	PinnedModel  string
	Verification *verify.Verification
}

// Verifications returns cached results without re-verifying them.
// Results may be expired or invalidated.
func (t *Transport) Verifications() []ReplicaVerification {
	results := []ReplicaVerification{}
	t.enclaves.Range(func(key, value any) bool {
		r := key.(replica)
		rt := value.(*verifiedReplicaTransport)
		if verified := rt.verification(); verified != nil {
			models := []string{}
			rt.models.Range(func(model, _ any) bool {
				models = append(models, model.(string))
				return true
			})
			slices.Sort(models)
			results = append(results, ReplicaVerification{Host: r.host, Models: models, Reference: r.ref, PinnedModel: r.model, Verification: verified})
		}
		return true
	})
	slices.SortFunc(results, func(a, b ReplicaVerification) int {
		return cmp.Or(strings.Compare(a.Host, b.Host),
			strings.Compare(a.Reference, b.Reference), strings.Compare(a.PinnedModel, b.PinnedModel))
	})
	return results
}

// Models returns the catalog's models that the policy serves, sorted, without
// verifying replicas.
func (t *Transport) Models(ctx context.Context) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	catalog, err := t.catalog(ctx)
	if err != nil {
		return nil, err
	}
	models := []string{}
	for model := range catalog {
		if _, _, err := t.policy.resolve(model, catalog); err == nil {
			models = append(models, model)
		}
	}
	slices.Sort(models)
	return models, nil
}

// EnsureVerified returns a valid verification of a replica serving model. It
// tries replicas in a fixed order for the model, so repeated calls verify the
// same replica while it stays valid, and stops once ctx is done.
func (t *Transport) EnsureVerified(ctx context.Context, model string) (*verify.Verification, error) {
	catalog, err := t.catalog(ctx)
	if err != nil {
		return nil, err
	}
	hosts, r, err := t.policy.resolve(model, catalog)
	if err != nil {
		return nil, err
	}
	for _, r.host = range rank(hosts, model, "") {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		var verified *verify.Verification
		if _, verified, err = t.verified(ctx, r); err == nil {
			return verified, nil
		}
	}
	return nil, err
}

type verifiedReplicaTransport struct {
	transport      http.RoundTripper
	verification   func() *verify.Verification
	ensureVerified func(context.Context) (*verify.Verification, error)
	models         sync.Map
}

func (t *verifiedReplicaTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.models.Store(req.Header.Get(modelHeader), struct{}{})
	return t.transport.RoundTrip(req)
}

func (t *verifiedReplicaTransport) CloseIdleConnections() {
	closeIdleConnections(t.transport)
}

func (t *Transport) reroutedHost(prefix string) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.rerouted[prefix]
}

func (t *Transport) remember(prefix, host string) {
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

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Each replica's binding makes the same check; making it here refuses a
	// request before the catalog is read or a replica verified.
	if err := enclave.EHBP.Check(req); err != nil {
		closeRequestBody(req)
		return nil, err
	}
	req = req.Clone(req.Context())
	if err := t.prepare(req); err != nil {
		return nil, err
	}
	model := req.Header.Get(modelHeader)
	catalog, err := t.catalog(req.Context())
	if err != nil {
		closeRequestBody(req)
		return nil, err
	}
	hosts, r, err := t.policy.resolve(model, catalog)
	if err != nil {
		closeRequestBody(req)
		return nil, err
	}
	hasBody := req.Body != nil && req.Body != http.NoBody
	replayable := !hasBody || req.GetBody != nil
	var rt *verifiedReplicaTransport
	prefix := req.Header.Get(cachePrefixHeader)
	for _, r.host = range rank(hosts, prefix, t.reroutedHost(prefix)) {
		if rt, _, err = t.verified(req.Context(), r); err == nil {
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
		resp, err := rt.RoundTrip(out)
		if err != nil {
			return nil, err
		}
		routed := resp.Header.Get(sealHeader)
		if resp.StatusCode != http.StatusPreconditionFailed || routed == "" || routed == r.host || !replayable {
			return resp, nil
		}
		resp.Body.Close()
		if redirects == maxSealRedirects {
			return nil, &errs.NetworkError{Err: fmt.Errorf("gateway kept routing away from the enclave the request was sealed to (last: %s)", routed)}
		}
		r.host = routed
		if rt, _, err = t.verified(req.Context(), r); err != nil {
			return nil, fmt.Errorf("following gateway route to enclave %s: %w", routed, err)
		}
		t.remember(prefix, routed)
	}
}

func (t *Transport) prepare(req *http.Request) error {
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
	scoped := transport.UserCacheSecretPathEligible(req)
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
		return &errs.ConfigurationError{Err: fmt.Errorf("multipart upload is missing its boundary")}
	}
	body, err := io.ReadAll(http.MaxBytesReader(nil, req.Body, maxMultipartBodySize))
	if err != nil {
		return fmt.Errorf("reading multipart upload: %w", err)
	}
	form, err := multipart.NewReader(bytes.NewReader(body), boundary).ReadForm(maxMultipartBodySize)
	if err != nil {
		return &errs.ConfigurationError{Err: fmt.Errorf("invalid multipart upload: %w", err)}
	}
	defer form.RemoveAll()
	models := form.Value["model"]
	if len(models) != 1 || strings.TrimSpace(models[0]) == "" || form.File["model"] != nil {
		return &errs.ConfigurationError{Err: fmt.Errorf("multipart upload must contain exactly one non-empty model field")}
	}
	req.Header.Set(modelHeader, models[0])
	setGatewayBody(req, body)
	return nil
}

// The engine only needs the salt; the secret itself never leaves the client.
func (t *Transport) scopeCache(h http.Header, fields map[string]json.RawMessage, body []byte) ([]byte, error) {
	var secret string
	json.Unmarshal(fields[transport.UserCacheSecretField], &secret)
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
	delete(fields, transport.UserCacheSecretField)
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

func closeIdleConnections(rt http.RoundTripper) {
	if closer, ok := rt.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

func closeRequestBody(req *http.Request) {
	if req.Body != nil {
		req.Body.Close()
	}
}
