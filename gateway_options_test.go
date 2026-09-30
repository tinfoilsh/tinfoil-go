package tinfoil

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/verifier/client"
	"github.com/tinfoilsh/tinfoil-go/verifier/measurement"
)

const gatewayTestURL = "https://gateway.example"
const gatewayTestRepo = "tinfoilsh/test"
const gatewayTestModel = "gpt-oss-120b"

func gatewayTestCatalog() Catalog {
	return Catalog{gatewayTestModel: {Repo: gatewayTestRepo, Hosts: []string{sealTestInitial}}}
}

func gatewayTestHTTP(t *testing.T, transport http.RoundTripper) {
	t.Helper()
	previousTransport, previousClient := http.DefaultTransport, http.DefaultClient
	http.DefaultTransport = transport
	http.DefaultClient = &http.Client{Transport: transport}
	t.Cleanup(func() { http.DefaultTransport, http.DefaultClient = previousTransport, previousClient })
}

func gatewayTestRequest(t *testing.T, g *Gateway, model string) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, gatewayTestURL+"/v1/chat/completions",
		strings.NewReader(`{"model":`+strconv.Quote(model)+`,"messages":[]}`))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	return g.HTTPClient().Do(req)
}

func TestGatewayConfigurationFailsBeforeIO(t *testing.T) {
	gatewayTestHTTP(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Error("invalid configuration must not access the network")
		return nil, errors.New("unexpected network access")
	}))
	badPins := &measurement.Measurement{Type: measurement.TdxGuestV2, Registers: []string{"invalid"}}
	for _, tc := range []struct {
		name string
		opts GatewayOptions
	}{
		{"client enclave", GatewayOptions{ClientOptions: []ClientOption{WithEnclave("enclave.example")}}},
		{"client repo", GatewayOptions{ClientOptions: []ClientOption{WithRepo(gatewayTestRepo)}}},
		{"client base URL", GatewayOptions{ClientOptions: []ClientOption{WithBaseURL(gatewayTestURL)}}},
		{"empty client base URL", GatewayOptions{ClientOptions: []ClientOption{WithBaseURL("")}}},
		{"TLS transport", GatewayOptions{ClientOptions: []ClientOption{WithTransport(TransportTLS)}}},
		{"unknown transport", GatewayOptions{ClientOptions: []ClientOption{WithTransport("unknown")}}},
		{"empty model", GatewayOptions{ModelPins: map[string]ModelPin{"": {Repo: gatewayTestRepo}}}},
		{"whitespace model", GatewayOptions{ModelPins: map[string]ModelPin{" \t": {Repo: gatewayTestRepo}}}},
		{"empty repo", GatewayOptions{ModelPins: map[string]ModelPin{gatewayTestModel: {}}}},
		{"malformed repo", GatewayOptions{ModelPins: map[string]ModelPin{gatewayTestModel: {Repo: "tinfoilsh/test/extra"}}}},
		{"malformed digest", GatewayOptions{ModelPins: map[string]ModelPin{gatewayTestModel: {Repo: gatewayTestRepo + "@sha256:bad"}}}},
		{"unsupported owner", GatewayOptions{ModelPins: map[string]ModelPin{gatewayTestModel: {Repo: "other/test"}}}},
		{"default registers", GatewayOptions{ClientOptions: []ClientOption{WithVerificationOptions(client.VerificationOptions{PinnedRegisters: badPins})}}},
		{"model registers", GatewayOptions{ModelPins: map[string]ModelPin{gatewayTestModel: {Repo: gatewayTestRepo, Verification: &client.VerificationOptions{PinnedRegisters: badPins}}}}},
		{"default freshness", GatewayOptions{ClientOptions: []ClientOption{WithVerificationOptions(client.VerificationOptions{FreshnessMaxAge: -time.Second})}}},
		{"model freshness", GatewayOptions{ModelPins: map[string]ModelPin{gatewayTestModel: {Repo: gatewayTestRepo, Verification: &client.VerificationOptions{FreshnessMaxAge: -time.Second}}}}},
		{"strict without pins", GatewayOptions{PinnedModelsOnly: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, catalog := range []func() Catalog{nil, func() Catalog { t.Fatal("constructor must not read callback"); return nil }} {
				_, err := NewGateway(gatewayTestURL, catalog, tc.opts)
				var config *ConfigurationError
				require.ErrorAs(t, err, &config)
			}
		})
	}
	for _, url := range []string{"", "gateway.example", "http://gateway.example", "://"} {
		_, err := NewGateway(url, nil, GatewayOptions{})
		var config *ConfigurationError
		require.ErrorAs(t, err, &config)
	}
	_, err := NewGateway(gatewayTestURL, nil, GatewayOptions{ModelPins: map[string]ModelPin{" ": {}}})
	require.ErrorContains(t, err, "name must not be empty")
	require.NotContains(t, err.Error(), "invalid release reference", "validation stops at the first error")
}

func TestGatewayCatalogEligibility(t *testing.T) {
	gatewayTestHTTP(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Error("eligibility must not access the network")
		return nil, errors.New("unexpected network access")
	}))
	catalog := gatewayTestCatalog()
	var calls int
	callback := func() Catalog { calls++; return catalog }
	g, err := NewGateway(gatewayTestURL, callback, GatewayOptions{
		ClientOptions: []ClientOption{WithUserCacheSecret("test")},
	})
	require.NoError(t, err)
	require.Zero(t, calls)
	require.True(t, g.Serves(gatewayTestModel))
	require.Equal(t, 1, calls)
	require.False(t, g.Serves("missing"))

	g, err = NewGateway(gatewayTestURL, callback, GatewayOptions{
		ClientOptions: []ClientOption{WithUserCacheSecret("test")},
		ModelPins: map[string]ModelPin{
			gatewayTestModel: {Repo: gatewayTestRepo + "@v1@sha256:" + strings.Repeat("a", 64)},
		},
		PinnedModelsOnly: true,
	})
	require.NoError(t, err)
	for _, tc := range []struct {
		entry  CatalogEntry
		serves bool
	}{
		{CatalogEntry{Repo: gatewayTestRepo, Hosts: []string{sealTestInitial}}, true},
		{CatalogEntry{Repo: "tinfoilsh/other", Hosts: []string{sealTestInitial}}, false},
		{CatalogEntry{Repo: gatewayTestRepo}, false},
		{CatalogEntry{Repo: gatewayTestRepo + "@v1", Hosts: []string{sealTestInitial}}, false},
		{CatalogEntry{Repo: gatewayTestRepo + "@sha256:" + strings.Repeat("a", 64), Hosts: []string{sealTestInitial}}, false},
		{CatalogEntry{Repo: "tinfoilsh/test/extra", Hosts: []string{sealTestInitial}}, false},
		{CatalogEntry{Repo: "other/test", Hosts: []string{sealTestInitial}}, false},
	} {
		catalog = Catalog{gatewayTestModel: tc.entry, "new-model": {Repo: gatewayTestRepo, Hosts: []string{sealTestInitial}}}
		require.Equal(t, tc.serves, g.Serves(gatewayTestModel), "%+v", tc.entry)
		require.False(t, g.Serves("new-model"))
		_, err := gatewayTestRequest(t, g, "new-model")
		var config *ConfigurationError
		require.ErrorAs(t, err, &config)
		if !tc.serves {
			_, err := gatewayTestRequest(t, g, gatewayTestModel)
			if tc.entry.Repo == "tinfoilsh/other" {
				var attestation *AttestationError
				require.ErrorAs(t, err, &attestation)
			} else {
				require.ErrorAs(t, err, &config)
			}
		}
	}
	catalog = nil
	require.False(t, g.Serves(gatewayTestModel))
	g, err = NewGateway(gatewayTestURL, callback, GatewayOptions{
		ClientOptions: []ClientOption{WithUserCacheSecret("test")},
		ModelPins: map[string]ModelPin{
			" Future Model ": {Repo: "tinfoilsh/Mixed.Case"},
		},
		PinnedModelsOnly: true,
	})
	require.NoError(t, err, "pins need not appear in the current catalog")
	catalog = Catalog{" Future Model ": {Repo: "tinfoilsh/Mixed.Case", Hosts: []string{sealTestInitial}}}
	require.True(t, g.Serves(" Future Model "))
	require.False(t, g.Serves("Future Model"))
	catalog = Catalog{" Future Model ": {Repo: "tinfoilsh/mixed.case", Hosts: []string{sealTestInitial}}}
	require.False(t, g.Serves(" Future Model "), "repository names are exact")
}

func TestGatewayRefusalClosesUploadWithoutReading(t *testing.T) {
	for _, model := range []string{"unpinned", "mismatch", gatewayTestModel} {
		t.Run(model, func(t *testing.T) {
			g, err := NewGateway(gatewayTestURL, func() Catalog {
				return Catalog{
					gatewayTestModel: {Repo: gatewayTestRepo, Hosts: []string{sealTestInitial}},
					"mismatch":       {Repo: "tinfoilsh/other", Hosts: []string{sealTestInitial}},
				}
			}, GatewayOptions{
				ClientOptions: []ClientOption{WithUserCacheSecret("test")},
				ModelPins: map[string]ModelPin{
					gatewayTestModel: {Repo: gatewayTestRepo},
					"mismatch":       {Repo: gatewayTestRepo},
				},
				PinnedModelsOnly: true,
			})
			require.NoError(t, err)
			g.seal.build = func(replica) (http.RoundTripper, error) { return nil, &AttestationError{Err: errors.New("rejected")} }
			body := &sealTestBody{Reader: strings.NewReader("private upload")}
			req, err := http.NewRequest(http.MethodPost, gatewayTestURL+"/upload", body)
			require.NoError(t, err)
			req.Header.Set(modelHeader, model)
			_, err = g.HTTPClient().Do(req)
			require.Error(t, err)
			require.Equal(t, 1, body.closes)
			require.Zero(t, body.reads)
		})
	}
}

func TestFetchCatalogDropsInvalidReferences(t *testing.T) {
	catalog := gatewayTestCatalog()
	for _, repo := range []string{"", "other/test", "tinfoilsh/", "tinfoilsh/test/extra", gatewayTestRepo + "@v1", gatewayTestRepo + "@sha256:" + strings.Repeat("a", 64)} {
		catalog[repo] = CatalogEntry{Repo: repo, Hosts: []string{sealTestInitial}}
	}
	catalog["no-hosts"] = CatalogEntry{Repo: gatewayTestRepo}
	payload, err := json.Marshal(catalog)
	require.NoError(t, err)
	var calls int
	gatewayTestHTTP(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		require.Equal(t, gatewayTestURL+catalogPath, req.URL.String())
		return newResponse(http.StatusOK, string(payload)), nil
	}))
	fetched, err := FetchCatalog("gateway.example")
	require.NoError(t, err)
	require.Equal(t, gatewayTestCatalog(), fetched)
	g, err := NewGateway(gatewayTestURL, nil, GatewayOptions{
		ClientOptions: []ClientOption{WithUserCacheSecret("test")},
	})
	require.NoError(t, err)
	require.True(t, g.Serves(gatewayTestModel))
	require.Equal(t, 2, calls, "nil callback fetches only once")
}

func TestGatewayMismatchRejectsBeforeCachedReplica(t *testing.T) {
	var network atomic.Int32
	gatewayTestHTTP(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		network.Add(1)
		return nil, errors.New("unexpected network access")
	}))
	catalog := gatewayTestCatalog()
	g, err := NewGateway(gatewayTestURL, func() Catalog { return catalog }, GatewayOptions{
		ClientOptions: []ClientOption{WithUserCacheSecret("test")},
		ModelPins: map[string]ModelPin{
			gatewayTestModel: {Repo: gatewayTestRepo},
		},
	})
	require.NoError(t, err)
	var sends int
	g.seal.enclaves.Store(replica{host: sealTestInitial, ref: gatewayTestRepo, model: gatewayTestModel}, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		req.Body.Close()
		sends++
		return newResponse(http.StatusNoContent, ""), nil
	}))
	resp, err := gatewayTestRequest(t, g, gatewayTestModel)
	require.NoError(t, err)
	resp.Body.Close()
	catalog = Catalog{gatewayTestModel: {Repo: "tinfoilsh/unexpected", Hosts: []string{sealTestInitial}}}
	_, err = gatewayTestRequest(t, g, gatewayTestModel)
	var attestation *AttestationError
	require.ErrorAs(t, err, &attestation)
	for _, part := range []string{gatewayTestModel, gatewayTestRepo, "tinfoilsh/unexpected"} {
		require.ErrorContains(t, err, part)
	}
	require.Equal(t, 1, sends)
	require.Zero(t, network.Load())
}

func TestGatewayRequestKeepsResolvedPolicyAcrossReroute(t *testing.T) {
	ref := gatewayTestRepo + "@v1"
	catalog := gatewayTestCatalog()
	var calls int
	g, err := NewGateway(gatewayTestURL, func() Catalog { calls++; return catalog }, GatewayOptions{
		ClientOptions: []ClientOption{WithUserCacheSecret("test")},
		ModelPins: map[string]ModelPin{
			gatewayTestModel: {Repo: ref},
		},
	})
	require.NoError(t, err)
	var seen []replica
	g.seal.build = func(r replica) (http.RoundTripper, error) {
		seen = append(seen, r)
		return roundTripFunc(func(req *http.Request) (*http.Response, error) {
			req.Body.Close()
			if r.host == sealTestInitial {
				catalog = Catalog{gatewayTestModel: {Repo: "tinfoilsh/changed", Hosts: []string{"changed.example"}}}
				return sealMismatch("next.example"), nil
			}
			return newResponse(http.StatusNoContent, ""), nil
		}), nil
	}
	resp, err := gatewayTestRequest(t, g, gatewayTestModel)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, 1, calls)
	require.Equal(t, []replica{{host: sealTestInitial, ref: ref, model: gatewayTestModel}, {host: "next.example", ref: ref, model: gatewayTestModel}}, seen)
	_, err = gatewayTestRequest(t, g, gatewayTestModel)
	var attestation *AttestationError
	require.ErrorAs(t, err, &attestation)
	require.Equal(t, 2, calls)
}

func TestGatewayOptionsPreserveCacheSecretAndOpenAIOrdering(t *testing.T) {
	t.Setenv(userCacheSecretEnv, "environment")
	for _, tc := range []struct{ secret, want string }{{"", "environment"}, {"explicit", "explicit"}} {
		g, err := NewGateway(gatewayTestURL, gatewayTestCatalog, GatewayOptions{
			ClientOptions: []ClientOption{
				nil,
				WithTransport(TransportEHBP),
				WithUserCacheSecret("first"),
				WithVerificationOptions(client.VerificationOptions{FreshnessMaxAge: time.Hour}),
				WithOpenAIOptions(option.WithHeader("X-Test", "first"), option.WithBaseURL("https://wrong.example"),
					option.WithHTTPClient(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
						t.Fatal("client options must not replace the sealing transport")
						return nil, nil
					})})),
				WithUserCacheSecret(tc.secret),
				WithVerificationOptions(client.VerificationOptions{FreshnessMaxAge: time.Minute}),
				WithOpenAIOptions(option.WithHeader("X-Test", "last"), option.WithAPIKey("sdk-test-api-key")),
				nil,
			},
		})
		require.NoError(t, err)
		require.Equal(t, tc.want, g.seal.secret)
		require.Equal(t, time.Minute, g.seal.policy.defaults.FreshnessMaxAge)
		g.seal.build = func(replica) (http.RoundTripper, error) {
			return roundTripFunc(func(req *http.Request) (*http.Response, error) {
				defer req.Body.Close()
				require.Equal(t, "gateway.example", req.URL.Host)
				require.Equal(t, "last", req.Header.Get("X-Test"))
				body, err := io.ReadAll(req.Body)
				require.NoError(t, err)
				salt, err := deriveCacheSalt("per-request", "sdk-test-api-key")
				require.NoError(t, err)
				require.Contains(t, string(body), salt)
				require.NotContains(t, string(body), "per-request")
				resp := newResponse(http.StatusOK, `{}`)
				resp.Header.Set("Content-Type", "application/json")
				return resp, nil
			}), nil
		}
		_, err = g.Chat.Completions.New(context.Background(), openai.ChatCompletionNewParams{Model: gatewayTestModel}, option.WithJSONSet("user_cache_secret", "per-request"))
		require.NoError(t, err)
	}
}

func TestGatewayDefaultPolicySnapshot(t *testing.T) {
	registers := []string{strings.Repeat("a", 96)}
	pins := &measurement.Measurement{Type: measurement.SevGuestV2, Registers: registers}
	opts := client.VerificationOptions{PinnedRegisters: pins, FreshnessMaxAge: time.Hour}
	g, err := NewGateway(gatewayTestURL, gatewayTestCatalog, GatewayOptions{
		ClientOptions: []ClientOption{
			WithUserCacheSecret("test"),
			WithVerificationOptions(opts),
		},
	})
	require.NoError(t, err)
	registers[0] = strings.Repeat("b", 96)
	pins.Type = measurement.TdxGuestV2
	opts.FreshnessMaxAge = -time.Second
	require.Equal(t, time.Hour, g.seal.policy.defaults.FreshnessMaxAge)
	require.Equal(t, measurement.SevGuestV2, g.seal.policy.defaults.PinnedRegisters.Type)
	require.Equal(t, []string{strings.Repeat("a", 96)}, g.seal.policy.defaults.PinnedRegisters.Registers)
	defaults, err := NewGateway(gatewayTestURL, gatewayTestCatalog, GatewayOptions{
		ClientOptions: []ClientOption{WithUserCacheSecret("test")},
	})
	require.NoError(t, err)
	require.Equal(t, 7*24*time.Hour, defaults.seal.policy.defaults.FreshnessMaxAge)
}

func TestGatewayModelPinsSnapshot(t *testing.T) {
	for _, remove := range []bool{false, true} {
		t.Run(strconv.FormatBool(remove), func(t *testing.T) {
			ref := gatewayTestRepo + "@v1"
			opts := GatewayOptions{
				ClientOptions:    []ClientOption{WithUserCacheSecret("test")},
				ModelPins:        map[string]ModelPin{gatewayTestModel: {Repo: ref}},
				PinnedModelsOnly: true,
			}
			catalog := gatewayTestCatalog()
			catalog["added"] = catalog[gatewayTestModel]
			g, err := NewGateway(gatewayTestURL, func() Catalog { return catalog }, opts)
			require.NoError(t, err)
			if remove {
				delete(opts.ModelPins, gatewayTestModel)
			} else {
				opts.ModelPins[gatewayTestModel] = ModelPin{Repo: "tinfoilsh/other"}
			}
			opts.ModelPins["added"] = ModelPin{Repo: gatewayTestRepo}
			opts.PinnedModelsOnly = false
			require.True(t, g.Serves(gatewayTestModel))
			require.False(t, g.Serves("added"))
			g.seal.build = func(r replica) (http.RoundTripper, error) {
				require.Equal(t, replica{host: sealTestInitial, ref: ref, model: gatewayTestModel}, r)
				return roundTripFunc(func(req *http.Request) (*http.Response, error) {
					req.Body.Close()
					return newResponse(http.StatusNoContent, ""), nil
				}), nil
			}
			resp, err := gatewayTestRequest(t, g, gatewayTestModel)
			require.NoError(t, err)
			resp.Body.Close()
			_, err = gatewayTestRequest(t, g, "added")
			var config *ConfigurationError
			require.ErrorAs(t, err, &config)
		})
	}
}
