package tinfoil

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/encrypted-http-body-protocol/protocol"
	"github.com/tinfoilsh/tinfoil-go/internal/testutil"
	"github.com/tinfoilsh/tinfoil-go/verifier"
	"github.com/tinfoilsh/tinfoil-go/verifier/client"
	"github.com/tinfoilsh/tinfoil-go/verifier/document"
	"github.com/tinfoilsh/tinfoil-go/verifier/measurement"
)

// Fetch real attestation evidence and intercept encrypted inference locally.
type gatewayLiveNetwork struct {
	fetches   atomic.Int32
	sends     atomic.Int32
	evidence  func(host string, raw []byte) ([]byte, error)
	inference func(*http.Request) *http.Response
}

func gatewayLiveHTTP(t *testing.T, enclave string) *gatewayLiveNetwork {
	t.Helper()
	n := &gatewayLiveNetwork{}
	upstream := http.DefaultTransport
	gatewayTestHTTP(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path == "/.well-known/tinfoil-attestation" {
			n.fetches.Add(1)
			host := req.URL.Query().Get("enclave")
			out := req.Clone(req.Context())
			out.URL.Host, out.Host = enclave, enclave
			q := out.URL.Query()
			q.Del("enclave")
			out.URL.RawQuery = q.Encode()
			resp, err := upstream.RoundTrip(out)
			if err != nil || n.evidence == nil {
				return resp, err
			}
			defer resp.Body.Close()
			raw, err := io.ReadAll(resp.Body)
			if err != nil {
				return nil, err
			}
			raw, err = n.evidence(host, raw)
			if err != nil {
				return nil, err
			}
			return newResponse(resp.StatusCode, string(raw)), nil
		}
		n.sends.Add(1)
		if req.Body != nil {
			defer req.Body.Close()
			body, err := io.ReadAll(req.Body)
			if err != nil {
				return nil, err
			}
			require.NotContains(t, string(body), "private test body", "inference must be sealed")
		}
		if n.inference != nil {
			return n.inference(req), nil
		}
		// EHBP passes through an empty error response from an intermediary.
		return newResponse(http.StatusTeapot, ""), nil
	}))
	return n
}

func liveGateway(t *testing.T, repo string, opts GatewayOptions) *Gateway {
	t.Helper()
	opts.ClientOptions = append([]ClientOption{WithUserCacheSecret("test")}, opts.ClientOptions...)
	g, err := NewGateway(gatewayTestURL, func() Catalog {
		return Catalog{gatewayTestModel: {Repo: repo, Hosts: []string{sealTestInitial}}}
	}, opts)
	require.NoError(t, err)
	return g
}

func liveGatewaySend(t *testing.T, g *Gateway, model string) error {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, gatewayTestURL+"/v1/audio/transcriptions", strings.NewReader("private test body"))
	require.NoError(t, err)
	req.Header.Set(modelHeader, model)
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := g.HTTPClient().Do(req)
	if resp != nil {
		resp.Body.Close()
	}
	return err
}

func TestLiveGatewayPinning(t *testing.T) {
	testutil.RequireLive(t, "TINFOIL_ENCLAVE", "TINFOIL_REPO")
	enclave, repo := os.Getenv("TINFOIL_ENCLAVE"), os.Getenv("TINFOIL_REPO")
	nonce, err := document.RandomNonce()
	require.NoError(t, err)
	raw, err := document.Fetch(enclave, nonce)
	require.NoError(t, err)
	verified, err := client.VerifyDocumentV3(raw, nonce, repo, nil)
	require.NoError(t, err)
	baseline, err := document.Parse(raw)
	require.NoError(t, err)
	repo, _, _, err = verifier.ParseReference(repo)
	require.NoError(t, err)
	ref := repo + "@sha256:" + verified.CodeDigest
	goodPins := func() *measurement.Measurement {
		return &measurement.Measurement{Type: verified.EnclaveMeasurement.Type, Registers: slices.Clone(verified.EnclaveMeasurement.Registers)}
	}
	badPins := func() *measurement.Measurement {
		pins := goodPins()
		pins.Registers[0] = strings.Repeat("ab", 48)
		require.NotEqual(t, verified.EnclaveMeasurement.Registers[0], pins.Registers[0])
		return pins
	}

	t.Run("digest and tag enforcement", func(t *testing.T) {
		n := gatewayLiveHTTP(t, enclave)
		for _, tc := range []struct {
			ref    string
			accept bool
		}{
			{ref, true},
			{repo + "@" + verified.CodeTag + "@sha256:" + verified.CodeDigest, true},
			{repo + "@sha256:" + strings.Repeat("a", 64), false},
			{repo + "@nonexistent-tag", false},
		} {
			g := liveGateway(t, repo, GatewayOptions{
				ModelPins: map[string]ModelPin{
					gatewayTestModel: {Repo: tc.ref},
				},
			})
			before := n.sends.Load()
			err := liveGatewaySend(t, g, gatewayTestModel)
			if tc.accept {
				require.NoError(t, err)
				require.Equal(t, before+1, n.sends.Load())
			} else {
				var attestation *AttestationError
				require.ErrorAs(t, err, &attestation)
				require.Equal(t, before, n.sends.Load())
			}
		}
	})

	t.Run("inheritance and complete replacement", func(t *testing.T) {
		n := gatewayLiveHTTP(t, enclave)
		for _, tc := range []struct {
			name     string
			defaults client.VerificationOptions
			model    *client.VerificationOptions
			accept   bool
		}{
			{"inherit registers", client.VerificationOptions{PinnedRegisters: badPins()}, nil, false},
			{"inherit freshness", client.VerificationOptions{FreshnessMaxAge: time.Nanosecond}, nil, false},
			{"replace registers", client.VerificationOptions{PinnedRegisters: badPins()}, &client.VerificationOptions{PinnedRegisters: goodPins()}, true},
			{"zero policy restores defaults", client.VerificationOptions{PinnedRegisters: badPins(), FreshnessMaxAge: time.Nanosecond}, &client.VerificationOptions{}, true},
			{"model registers enforced", client.VerificationOptions{}, &client.VerificationOptions{PinnedRegisters: badPins()}, false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				g := liveGateway(t, repo, GatewayOptions{
					ClientOptions: []ClientOption{WithVerificationOptions(tc.defaults)},
					ModelPins: map[string]ModelPin{
						gatewayTestModel: {Repo: ref, Verification: tc.model},
					},
				})
				before := n.sends.Load()
				err := liveGatewaySend(t, g, gatewayTestModel)
				if tc.accept {
					require.NoError(t, err)
					require.Equal(t, before+1, n.sends.Load())
				} else {
					var attestation *AttestationError
					require.ErrorAs(t, err, &attestation)
					require.Equal(t, before, n.sends.Load())
				}
			})
		}
	})

	t.Run("model isolation and unpinned sharing", func(t *testing.T) {
		n := gatewayLiveHTTP(t, enclave)
		entry := CatalogEntry{Repo: repo, Hosts: []string{sealTestInitial}}
		g, err := NewGateway(gatewayTestURL, func() Catalog {
			return Catalog{gatewayTestModel: entry, "bad-model": entry, "unpinned": entry, "also-unpinned": entry}
		}, GatewayOptions{
			ClientOptions: []ClientOption{WithUserCacheSecret("test")},
			ModelPins: map[string]ModelPin{
				gatewayTestModel: {Repo: ref, Verification: &client.VerificationOptions{PinnedRegisters: goodPins()}},
				"bad-model":      {Repo: ref, Verification: &client.VerificationOptions{PinnedRegisters: badPins()}},
			},
		})
		require.NoError(t, err)
		require.NoError(t, liveGatewaySend(t, g, gatewayTestModel))
		var attestation *AttestationError
		require.ErrorAs(t, liveGatewaySend(t, g, "bad-model"), &attestation)
		require.EqualValues(t, 1, n.sends.Load(), "warming one model cannot authorize another")
		require.NoError(t, liveGatewaySend(t, g, "unpinned"))
		fetches := n.fetches.Load()
		require.NoError(t, liveGatewaySend(t, g, "also-unpinned"))
		require.Equal(t, fetches, n.fetches.Load(), "unpinned models share the default policy")
	})

	t.Run("caller mutation and newly discovered replicas", func(t *testing.T) {
		n := gatewayLiveHTTP(t, enclave)
		defaults := client.VerificationOptions{PinnedRegisters: goodPins()}
		model := client.VerificationOptions{PinnedRegisters: goodPins()}
		pin := ModelPin{Repo: ref, Verification: &model}
		catalog := Catalog{}
		g, err := NewGateway(gatewayTestURL, func() Catalog { return catalog }, GatewayOptions{
			ClientOptions: []ClientOption{
				WithUserCacheSecret("test"),
				WithVerificationOptions(defaults),
			},
			ModelPins: map[string]ModelPin{
				gatewayTestModel: pin,
				"inherited":      {Repo: ref},
			},
		})
		require.NoError(t, err)
		for i, host := range []string{sealTestInitial, "new.example"} {
			entry := CatalogEntry{Repo: repo, Hosts: []string{host}}
			catalog = Catalog{gatewayTestModel: entry, "inherited": entry, "unpinned": entry}
			if i == 0 {
				defaults.PinnedRegisters.Registers[0] = badPins().Registers[0]
				model.PinnedRegisters.Registers[0] = badPins().Registers[0]
				defaults.PinnedRegisters.Type, model.PinnedRegisters.Type = "invalid", "invalid"
				defaults.FreshnessMaxAge, model.FreshnessMaxAge = -time.Second, -time.Second
				pin.Repo = "other/repo"
			}
			for _, name := range []string{gatewayTestModel, "inherited", "unpinned"} {
				require.NoError(t, liveGatewaySend(t, g, name))
			}
		}
		require.EqualValues(t, 6, n.fetches.Load())
		require.EqualValues(t, 6, n.sends.Load())
	})

	corrupt := func(raw []byte) ([]byte, error) {
		doc, err := document.Parse(raw)
		if err != nil {
			return nil, err
		}
		for i := range doc.Collateral {
			if doc.Collateral[i].Format == document.CollateralSigstoreCodeV1Format {
				doc.Collateral[i].Data = []byte(`{"sigstore_bundle":{}}`)
			}
		}
		return json.Marshal(doc)
	}
	for _, accept := range []bool{true, false} {
		name := "reroute accepted"
		if !accept {
			name = "reroute rejected before replay"
		}
		t.Run(name, func(t *testing.T) {
			n := gatewayLiveHTTP(t, enclave)
			n.evidence = func(host string, raw []byte) ([]byte, error) {
				if !accept && host == "next.example" {
					return corrupt(raw)
				}
				return raw, nil
			}
			n.inference = func(req *http.Request) *http.Response {
				if req.Header.Get(sealHeader) == sealTestInitial {
					return sealMismatch("next.example")
				}
				return newResponse(http.StatusTeapot, "")
			}
			g := liveGateway(t, repo, GatewayOptions{
				ModelPins: map[string]ModelPin{
					gatewayTestModel: {Repo: ref, Verification: &client.VerificationOptions{PinnedRegisters: goodPins()}},
				},
			})
			req, err := http.NewRequest(http.MethodPost, gatewayTestURL+"/upload", strings.NewReader("private test body"))
			require.NoError(t, err)
			req.Header.Set(modelHeader, gatewayTestModel)
			var replays int
			req.GetBody = func() (io.ReadCloser, error) {
				replays++
				return io.NopCloser(strings.NewReader("private test body")), nil
			}
			resp, err := g.HTTPClient().Do(req)
			if accept {
				require.NoError(t, err)
				resp.Body.Close()
				require.EqualValues(t, 2, n.sends.Load())
				require.Equal(t, 1, replays)
			} else {
				var attestation *AttestationError
				require.ErrorAs(t, err, &attestation)
				require.EqualValues(t, 1, n.sends.Load())
				require.Zero(t, replays)
			}
		})
	}

	t.Run("failed candidate is skipped under the same pin", func(t *testing.T) {
		n := gatewayLiveHTTP(t, enclave)
		hosts := []string{sealTestInitial, "next.example"}
		const prefix = "test-prefix"
		first := rank(hosts, prefix, "")[0]
		n.evidence = func(host string, raw []byte) ([]byte, error) {
			if host == first {
				return corrupt(raw)
			}
			return raw, nil
		}
		g, err := NewGateway(gatewayTestURL, func() Catalog { return Catalog{gatewayTestModel: {Repo: repo, Hosts: hosts}} }, GatewayOptions{
			ClientOptions: []ClientOption{WithUserCacheSecret("test")},
			ModelPins: map[string]ModelPin{
				gatewayTestModel: {Repo: ref},
			},
		})
		require.NoError(t, err)
		req, err := http.NewRequest(http.MethodGet, gatewayTestURL+"/test", nil)
		require.NoError(t, err)
		req.Header.Set(modelHeader, gatewayTestModel)
		req.Header.Set(cachePrefixHeader, prefix)
		resp, err := g.HTTPClient().Do(req)
		require.NoError(t, err)
		resp.Body.Close()
		require.EqualValues(t, 1, n.sends.Load())
		require.GreaterOrEqual(t, n.fetches.Load(), int32(3))
	})

	t.Run("key rotation retains policy snapshot", func(t *testing.T) {
		n := gatewayLiveHTTP(t, enclave)
		opts := client.VerificationOptions{PinnedRegisters: goodPins()}
		g := liveGateway(t, repo, GatewayOptions{
			ClientOptions: []ClientOption{WithVerificationOptions(client.VerificationOptions{PinnedRegisters: badPins()})},
			ModelPins: map[string]ModelPin{
				gatewayTestModel: {Repo: ref, Verification: &opts},
			},
		})
		require.NoError(t, liveGatewaySend(t, g, gatewayTestModel))
		opts.PinnedRegisters.Registers[0] = badPins().Registers[0]
		opts.FreshnessMaxAge = time.Nanosecond
		n.inference = func(*http.Request) *http.Response {
			if n.sends.Load() == 2 {
				resp := newResponse(http.StatusUnprocessableEntity, `{"type":"`+protocol.KeyConfigProblemType+`"}`)
				resp.Header.Set("Content-Type", protocol.ProblemJSONMediaType)
				return resp
			}
			return newResponse(http.StatusTeapot, "")
		}
		require.NoError(t, liveGatewaySend(t, g, gatewayTestModel))
		require.EqualValues(t, 2, n.fetches.Load())
		require.EqualValues(t, 3, n.sends.Load())
	})

	t.Run("expiry retains model freshness bound", func(t *testing.T) {
		n := gatewayLiveHTTP(t, enclave)
		// Keep the original signed witnesses while fetching fresh nonce-bound
		// quotes, so a witness renewal cannot move the deadline during the test.
		n.evidence = func(_ string, raw []byte) ([]byte, error) {
			doc, err := document.Parse(raw)
			if err != nil {
				return nil, err
			}
			doc.Collateral = slices.DeleteFunc(doc.Collateral, func(c document.CollateralEntry) bool {
				return c.Format == document.CollateralSigstoreFreshnessV1Format
			})
			for _, c := range baseline.Collateral {
				if c.Format == document.CollateralSigstoreFreshnessV1Format {
					doc.Collateral = append(doc.Collateral, c)
				}
			}
			return json.Marshal(doc)
		}
		const lifetime = 3 * time.Second
		defaults, err := verifier.New()
		require.NoError(t, err)
		witnessedAt := verified.FreshnessExpiresAt.Add(-defaults.FreshnessMaxAge())
		maxAge := time.Since(witnessedAt) + lifetime
		g := liveGateway(t, repo, GatewayOptions{
			ModelPins: map[string]ModelPin{
				gatewayTestModel: {Repo: ref, Verification: &client.VerificationOptions{FreshnessMaxAge: maxAge}},
			},
		})
		require.NoError(t, liveGatewaySend(t, g, gatewayTestModel))
		time.Sleep(time.Until(witnessedAt.Add(maxAge)))
		var attestation *AttestationError
		require.ErrorAs(t, liveGatewaySend(t, g, gatewayTestModel), &attestation)
		require.Greater(t, n.fetches.Load(), int32(1))
		require.EqualValues(t, 1, n.sends.Load())
	})
}
