package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/internal/cachesecret"
	"github.com/tinfoilsh/tinfoil-go/internal/errs"
	"github.com/tinfoilsh/tinfoil-go/internal/verifytest"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func staticCatalog(catalog Catalog) func(context.Context) (Catalog, error) {
	return func(context.Context) (Catalog, error) { return catalog, nil }
}

func newResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}
}

const (
	sealTestModel   = "test-model"
	sealTestInitial = "initial.example"
)

// sealTestTransport serves each replica through the transport connect returns
// for its host. Like a transport verifying, a replica calls connect until it
// succeeds, then reuses the result.
func sealTestTransport(connect func(host string) (http.RoundTripper, error)) *Transport {
	return &Transport{
		build: func(r replica) (*verifiedReplicaTransport, error) {
			var mu sync.Mutex
			var verified http.RoundTripper
			return &verifiedReplicaTransport{
				transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					mu.Lock()
					defer mu.Unlock()
					return verified.RoundTrip(req)
				}),
				ensureVerified: func(context.Context) (*verify.Verification, error) {
					mu.Lock()
					defer mu.Unlock()
					if verified == nil {
						transport, err := connect(r.host)
						if err != nil {
							return nil, err
						}
						verified = transport
					}
					return nil, nil
				},
			}, nil
		},
		catalog: staticCatalog(Catalog{sealTestModel: {Repo: "tinfoilsh/test", Hosts: []string{sealTestInitial}}}),
	}
}

func sealMismatch(enclave string) *http.Response {
	resp := newResponse(http.StatusPreconditionFailed, "")
	resp.Header.Set(sealHeader, enclave)
	return resp
}

func TestSealRerouteIsPerRequest(t *testing.T) {
	verificationErr := errors.New("verification failed")
	var nextBuilds, initialHits int
	seal := sealTestTransport(func(host string) (http.RoundTripper, error) {
		if host != sealTestInitial {
			nextBuilds++
			if nextBuilds == 1 {
				return nil, verificationErr
			}
		}
		return roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if host == sealTestInitial {
				initialHits++
				return sealMismatch("next.example"), nil
			}
			return newResponse(http.StatusNoContent, ""), nil
		}), nil
	})
	get := func() (*http.Response, error) {
		req, err := http.NewRequest(http.MethodGet, "https://gateway.example/reroute", nil)
		require.NoError(t, err)
		req.Header.Set(modelHeader, sealTestModel)
		return seal.RoundTrip(req)
	}
	_, err := get()
	require.ErrorIs(t, err, verificationErr)
	for range 2 {
		resp, err := get()
		require.NoError(t, err)
		resp.Body.Close()
	}
	require.Equal(t, 3, initialHits, "every request starts from its own pick, not the last reroute")
	require.Equal(t, 2, nextBuilds, "a failed verification is retried, a successful one is reused")
}

type sealTestBody struct {
	io.Reader
	reads, closes int
}

func (b *sealTestBody) Read(p []byte) (int, error) {
	b.reads++
	return b.Reader.Read(p)
}

func (b *sealTestBody) Close() error {
	b.closes++
	return nil
}

func TestSealRefusesUpgradesBeforeTouchingReplicas(t *testing.T) {
	tr := sealTestTransport(func(string) (http.RoundTripper, error) {
		t.Error("an upgrade reached a replica")
		return nil, errors.New("unreachable")
	})
	tr.catalog = func(context.Context) (Catalog, error) {
		t.Error("an upgrade read the catalog")
		return nil, errors.New("unreachable")
	}
	req, _ := http.NewRequest(http.MethodGet, "https://gateway.example/v1/realtime?model="+sealTestModel, nil)
	req.Header.Set(modelHeader, sealTestModel)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	_, err := tr.RoundTrip(req)
	var config *errs.ConfigurationError
	require.ErrorAs(t, err, &config)
	require.ErrorContains(t, err, "WebSocket")
}

func TestSealUploadReplay(t *testing.T) {
	const payload = "upload contents"
	replayErr := errors.New("cannot reopen upload")
	for _, tc := range []struct {
		name      string
		getBody   bool
		replayErr error
	}{
		{name: "replays", getBody: true},
		{name: "no GetBody"},
		{name: "GetBody fails", getBody: true, replayErr: replayErr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := &sealTestBody{Reader: strings.NewReader(payload)}
			replayed := &sealTestBody{Reader: strings.NewReader(payload)}
			responseBody := &sealTestBody{Reader: strings.NewReader("")}
			var attempts int
			seal := sealTestTransport(func(host string) (http.RoundTripper, error) {
				return roundTripFunc(func(req *http.Request) (*http.Response, error) {
					defer req.Body.Close()
					attempts++
					if host == sealTestInitial {
						require.Same(t, original, req.Body)
						require.Zero(t, original.reads, "headers must reach the transport before the upload is read")
						resp := sealMismatch("next.example")
						resp.Body = responseBody
						return resp, nil
					}
					require.Same(t, replayed, req.Body)
					body, err := io.ReadAll(req.Body)
					require.NoError(t, err)
					require.Equal(t, payload, string(body))
					return newResponse(http.StatusNoContent, ""), nil
				}), nil
			})
			req, err := http.NewRequest(http.MethodPost, "https://gateway.example/v1/audio/transcriptions", original)
			require.NoError(t, err)
			req.Header.Set("Content-Type", "multipart/form-data; boundary=test")
			req.Header.Set(modelHeader, sealTestModel)
			if tc.getBody {
				req.GetBody = func() (io.ReadCloser, error) {
					if tc.replayErr != nil {
						return nil, tc.replayErr
					}
					return replayed, nil
				}
			}
			resp, err := seal.RoundTrip(req)
			require.Equal(t, 1, original.closes)
			switch {
			case !tc.getBody:
				require.NoError(t, err)
				require.Equal(t, http.StatusPreconditionFailed, resp.StatusCode)
				require.Equal(t, 1, attempts)
				require.Zero(t, responseBody.closes, "the caller owns the returned response")
				resp.Body.Close()
			case tc.replayErr != nil:
				require.ErrorIs(t, err, tc.replayErr)
				require.Nil(t, resp)
				require.Equal(t, 1, attempts)
				require.Equal(t, 1, responseBody.closes)
			default:
				require.NoError(t, err)
				require.Equal(t, http.StatusNoContent, resp.StatusCode)
				require.Equal(t, 2, attempts)
				require.Equal(t, 1, responseBody.closes)
				require.Equal(t, 1, replayed.closes)
				resp.Body.Close()
			}
		})
	}
}

// The cache salt and prefix of SPEC §14.7.4's vector: secret test-secret,
// Authorization: Bearer test-api-key, and specCacheBody.
const (
	specCacheBody   = `{"model":"test-model","messages":[{"role":"user","content":"hello"}]}`
	specCacheSalt   = "DpKycpNLBpMrAyjpNCVBx66rSpZVwsZJPz5Ty66bBy8"
	specCachePrefix = "ede1ce81b1779c5d9431ab8d3a073b06a8507da5cc3178ff385c13cef8ff02f6"
)

func TestSealJSONRoutingPreservesInjectedBodyAcrossRetries(t *testing.T) {
	for _, contentType := range []string{"application/json", "application/json; charset=utf-8"} {
		t.Run("contentType="+contentType, func(t *testing.T) {
			var bodies []string
			var prefixes []string
			seal := sealTestTransport(func(host string) (http.RoundTripper, error) {
				return roundTripFunc(func(req *http.Request) (*http.Response, error) {
					defer req.Body.Close()
					body, err := io.ReadAll(req.Body)
					require.NoError(t, err)
					bodies = append(bodies, string(body))
					require.Equal(t, "test-model", req.Header.Get(modelHeader))
					require.Equal(t, host, req.Header.Get(sealHeader))
					prefixes = append(prefixes, req.Header.Get(cachePrefixHeader))
					if host == sealTestInitial {
						return sealMismatch("next.example"), nil
					}
					return newResponse(http.StatusNoContent, ""), nil
				}), nil
			})
			seal.secret = "test-secret"
			req, err := http.NewRequest(http.MethodPost, "https://gateway.example/v1/chat/completions", strings.NewReader(specCacheBody))
			require.NoError(t, err)
			req.Header.Set("Content-Type", contentType)
			req.Header.Set("Authorization", "Bearer test-api-key")
			resp, err := seal.RoundTrip(req)
			require.NoError(t, err)
			resp.Body.Close()
			require.Len(t, bodies, 2)
			require.Equal(t, bodies[0], bodies[1])
			var fields map[string]json.RawMessage
			require.NoError(t, json.Unmarshal([]byte(bodies[0]), &fields))
			require.NotContains(t, fields, cachesecret.Field)
			require.JSONEq(t, `"`+specCacheSalt+`"`, string(fields[cacheSaltField]))
			require.Equal(t, specCachePrefix, prefixes[0])
			require.Equal(t, prefixes[0], prefixes[1])
			require.Empty(t, req.Header.Get(modelHeader))
			require.Empty(t, req.Header.Get(cachePrefixHeader))
			require.Empty(t, req.Header.Get(sealHeader))
		})
	}
}

func TestSealFallsOverToAReplicaThatVerifies(t *testing.T) {
	hosts := []string{"a.example", "b.example", "c.example"}
	order := rank(hosts, specCachePrefix, "")
	failure := errors.New("verification failed")
	var verified, sent []string
	seal := sealTestTransport(func(host string) (http.RoundTripper, error) {
		verified = append(verified, host)
		if host != order[2] {
			return nil, failure
		}
		return roundTripFunc(func(req *http.Request) (*http.Response, error) {
			req.Body.Close()
			sent = append(sent, req.Header.Get(sealHeader))
			return newResponse(http.StatusNoContent, ""), nil
		}), nil
	})
	seal.catalog = staticCatalog(Catalog{sealTestModel: {Repo: "tinfoilsh/test", Hosts: hosts}})
	seal.secret = "test-secret"
	req, err := http.NewRequest(http.MethodPost, "https://gateway.example/v1/chat/completions", strings.NewReader(specCacheBody))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-api-key")
	resp, err := seal.RoundTrip(req)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, order, verified, "replicas are verified in rank order until one passes")
	require.Equal(t, []string{order[2]}, sent, "the request is sealed only to a replica that verified")
}

// sealCacheScope sends body through a gateway transport whose client-level
// secret is clientSecret, and returns the cache_salt and cache prefix the
// replica received.
func sealCacheScope(t *testing.T, clientSecret, authorization, body string) (json.RawMessage, string) {
	t.Helper()
	var fields map[string]json.RawMessage
	var prefix string
	seal := sealTestTransport(func(string) (http.RoundTripper, error) {
		return roundTripFunc(func(req *http.Request) (*http.Response, error) {
			defer req.Body.Close()
			require.NoError(t, json.NewDecoder(req.Body).Decode(&fields))
			prefix = req.Header.Get(cachePrefixHeader)
			return newResponse(http.StatusNoContent, ""), nil
		}), nil
	})
	seal.secret = clientSecret
	req, err := http.NewRequest(http.MethodPost, "https://gateway.example/v1/chat/completions", strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	resp, err := seal.RoundTrip(req)
	require.NoError(t, err)
	resp.Body.Close()
	require.NotContains(t, fields, cachesecret.Field, "the secret never leaves the client")
	return fields[cacheSaltField], prefix
}

func TestSealPerRequestCacheSecretOverridesClientSecret(t *testing.T) {
	gotSalt, gotPrefix := sealCacheScope(t, "client-secret", "Bearer test-api-key", `{"model":"test-model","user_cache_secret":"end-user"}`)
	wantSalt, wantPrefix := sealCacheScope(t, "end-user", "Bearer test-api-key", `{"model":"test-model"}`)
	require.Equal(t, wantSalt, gotSalt)
	require.Equal(t, wantPrefix, gotPrefix)
	clientSalt, _ := sealCacheScope(t, "client-secret", "Bearer test-api-key", `{"model":"test-model"}`)
	require.NotEqual(t, clientSalt, gotSalt)
}

func TestSealCacheScopeUsesTheBearerCredential(t *testing.T) {
	for _, authorization := range []string{"Bearer test-api-key", "bearer test-api-key", " BEARER  test-api-key "} {
		salt, prefix := sealCacheScope(t, "test-secret", authorization, specCacheBody)
		require.JSONEq(t, `"`+specCacheSalt+`"`, string(salt), "%q", authorization)
		require.Equal(t, specCachePrefix, prefix, "%q", authorization)
	}

	noKeySalt, noKeyPrefix := sealCacheScope(t, "test-secret", "", specCacheBody)
	for _, authorization := range []string{"Basic test-api-key", "Bearertest-api-key", "Bearer"} {
		salt, prefix := sealCacheScope(t, "test-secret", authorization, specCacheBody)
		require.Equal(t, noKeySalt, salt, "%q carries no Bearer credential", authorization)
		require.Equal(t, noKeyPrefix, prefix, "%q carries no Bearer credential", authorization)
	}

	otherSalt, otherPrefix := sealCacheScope(t, "test-secret", "Bearer other-api-key", specCacheBody)
	for _, salt := range []json.RawMessage{noKeySalt, otherSalt} {
		require.NotEqual(t, `"`+specCacheSalt+`"`, string(salt), "each API key scopes its own cache")
	}
	for _, prefix := range []string{noKeyPrefix, otherPrefix} {
		require.NotEqual(t, specCachePrefix, prefix, "each API key routes on its own prefix")
	}
	require.NotEqual(t, noKeySalt, otherSalt, "each API key scopes its own cache")
	require.NotEqual(t, noKeyPrefix, otherPrefix, "each API key routes on its own prefix")
}

func TestGatewayVerificationsNameReplicaHosts(t *testing.T) {
	seal := &Transport{}
	for _, host := range []string{"b.example", "a.example"} {
		verified := verifytest.New(verifytest.Fields{ConfigRepo: "tinfoilsh/model"})
		seal.enclaves.Store(replica{host: host, ref: "tinfoilsh/model"}, &verifiedReplicaTransport{
			verification: func() *verify.Verification { return verified },
		})
	}
	got := seal.Verifications()
	require.Len(t, got, 2)
	require.Equal(t, "a.example", got[0].Host)
	require.Equal(t, "b.example", got[1].Host)
}

func TestGatewayEnsureVerifiedFallsOver(t *testing.T) {
	verified := verifytest.New(verifytest.Fields{ConfigRepo: "tinfoilsh/test"})
	failure := errors.New("verification failed")
	hosts := []string{"a.example", "b.example", "c.example"}
	order := rank(hosts, sealTestModel, "")
	buildFails, expired := order[0], order[1]
	catalog := staticCatalog(Catalog{sealTestModel: {Repo: "tinfoilsh/test", Hosts: hosts}})
	newGateway := func(attempts *[]string, build func(replica) (*verifiedReplicaTransport, error)) *Transport {
		return &Transport{catalog: catalog, build: func(r replica) (*verifiedReplicaTransport, error) {
			*attempts = append(*attempts, r.host)
			return build(r)
		}}
	}

	var attempts []string
	seal := newGateway(&attempts, func(r replica) (*verifiedReplicaTransport, error) {
		switch r.host {
		case buildFails:
			return nil, failure
		case expired:
			return &verifiedReplicaTransport{ensureVerified: func(context.Context) (*verify.Verification, error) { return nil, failure }}, nil
		}
		return &verifiedReplicaTransport{ensureVerified: func(context.Context) (*verify.Verification, error) { return verified, nil }}, nil
	})
	got, err := seal.EnsureVerified(context.Background(), sealTestModel)
	require.NoError(t, err)
	require.Same(t, verified, got)
	require.Equal(t, order, attempts, "replicas are tried in the model's fixed order until one verifies")

	attempts = nil
	unreachable := newGateway(&attempts, func(replica) (*verifiedReplicaTransport, error) { return nil, failure })
	_, err = unreachable.EnsureVerified(context.Background(), sealTestModel)
	require.ErrorIs(t, err, failure)
	require.Equal(t, order, attempts)

	attempts = nil
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = newGateway(&attempts, func(replica) (*verifiedReplicaTransport, error) { return nil, failure }).EnsureVerified(ctx, sealTestModel)
	require.ErrorIs(t, err, context.Canceled)
	require.Empty(t, attempts, "a done context stops before any replica is built")
}

func TestGatewayKeepsOneTransportPerReplica(t *testing.T) {
	arrived, proceed := make(chan struct{}, 2), make(chan struct{})
	seal := &Transport{build: func(replica) (*verifiedReplicaTransport, error) {
		arrived <- struct{}{}
		<-proceed
		return &verifiedReplicaTransport{}, nil
	}}
	results := make(chan *verifiedReplicaTransport, 2)
	for range 2 {
		go func() {
			rt, _ := seal.enclave(replica{host: "a.example"})
			results <- rt
		}()
	}
	<-arrived
	<-arrived
	close(proceed)
	first, second := <-results, <-results
	require.NotNil(t, first)
	// One transport means one verification, whose refresh concurrent requests
	// share; internal/transport tests that.
	require.Same(t, first, second, "concurrent first uses share one replica transport")
}

// testKeyRejection is a key rejection as transport.IsKeyRejection reports one.
type testKeyRejection struct{ error }

func (testKeyRejection) KeyRejected() bool { return true }

func TestReplicaChainReplaysAndNamesTheReplica(t *testing.T) {
	var attempts []*http.Request
	conn := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		req.Body.Close()
		attempts = append(attempts, req)
		if len(attempts) == 1 {
			return nil, testKeyRejection{errors.New("rotated key")}
		}
		return newResponse(http.StatusOK, ""), nil
	})
	rt := replicaChain(conn, "replica.example", "https://gateway.example/v1/")
	req, err := http.NewRequest(http.MethodPost, "https://gateway.example/v1/chat/completions", strings.NewReader(`{"model":"m"}`))
	require.NoError(t, err)
	resp, err := rt.RoundTrip(req)
	require.NoError(t, err)
	resp.Body.Close()
	require.Len(t, attempts, 2, "a key rejection is replayed once")
	for _, attempt := range attempts {
		require.Equal(t, "https://replica.example", attempt.Header.Get("X-Tinfoil-Enclave-Url"), "SPEC 14.7: every attempt names the replica")
	}
}
