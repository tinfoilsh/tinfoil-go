package tinfoil

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/internal/errs"
	"github.com/tinfoilsh/tinfoil-go/internal/fetch"
	"github.com/tinfoilsh/tinfoil-go/internal/sdkinfo"
	"github.com/tinfoilsh/tinfoil-go/internal/testutil"
	"github.com/tinfoilsh/tinfoil-go/verify/document"
)

// refuseDirectFetches fails the test if anything is fetched with the default
// HTTP client or transport, which every direct fetch uses. A request whose
// context is already done sends nothing, so it only fails.
func refuseDirectFetches(t *testing.T) {
	t.Helper()
	client, transport := http.DefaultClient, http.DefaultTransport
	t.Cleanup(func() { http.DefaultClient, http.DefaultTransport = client, transport })
	refuse := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if err := req.Context().Err(); err != nil {
			return nil, err
		}
		t.Errorf("nothing is fetched directly, but %s was", req.URL)
		return nil, errors.New("no network in this test")
	})
	http.DefaultClient = &http.Client{Transport: refuse}
	http.DefaultTransport = refuse
}

// fetchCall is one call to a recordingFetcher.
type fetchCall struct {
	host  string
	nonce []byte
}

// recordingFetcher records each call and returns its result.
type recordingFetcher struct {
	mu     sync.Mutex
	calls  []fetchCall
	result func(ctx context.Context, host string, nonce []byte) ([]byte, error)
}

func (f *recordingFetcher) FetchAttestation(ctx context.Context, host string, nonce []byte) ([]byte, error) {
	f.mu.Lock()
	f.calls = append(f.calls, fetchCall{host, nonce})
	f.mu.Unlock()
	return f.result(ctx, host, nonce)
}

func (f *recordingFetcher) hosts() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var hosts []string
	for _, c := range f.calls {
		hosts = append(hosts, c.host)
	}
	return hosts
}

func TestFetcherOptionsAreCheckedBeforeNetworkIO(t *testing.T) {
	refuseDirectFetches(t)
	// A done context makes discovery itself fail, so only a check made before
	// discovery reports ErrConfiguration.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	invalid := map[string]struct {
		attestation AttestationFetcher
		list        RouterListFetcher
	}{
		"empty URL":                 {AttestationRelay{}, RouterListRelay{}},
		"plaintext remote URL":      {AttestationRelay{URL: "http://app.example/tinfoil"}, RouterListRelay{URL: "http://app.example/tinfoil"}},
		"relative URL":              {AttestationRelay{URL: "/tinfoil"}, RouterListRelay{URL: "/tinfoil"}},
		"other scheme":              {AttestationRelay{URL: "ftp://app.example"}, RouterListRelay{URL: "ftp://app.example"}},
		"user information":          {AttestationRelay{URL: "https://user:pass@app.example"}, RouterListRelay{URL: "https://user:pass@app.example"}},
		"empty query":               {AttestationRelay{URL: "https://app.example/?"}, RouterListRelay{URL: "https://app.example/?"}},
		"query":                     {AttestationRelay{URL: "https://app.example/?a=1"}, RouterListRelay{URL: "https://app.example/?a=1"}},
		"empty fragment":            {AttestationRelay{URL: "https://app.example/#"}, RouterListRelay{URL: "https://app.example/#"}},
		"pointer to an invalid URL": {&AttestationRelay{URL: "http://app.example"}, &RouterListRelay{URL: "http://app.example"}},
		"nil pointer":               {(*AttestationRelay)(nil), (*RouterListRelay)(nil)},
		"nil function":              {AttestationFetcherFunc(nil), RouterListFetcherFunc(nil)},
	}
	for name, tc := range invalid {
		t.Run(name, func(t *testing.T) {
			_, err := unverifiedEnclaveHTTPClient("enclave.example", RepoPin{Repo: "org/repo"}, &EnclaveOptions{FetchAttestation: tc.attestation})
			require.ErrorIs(t, err, ErrConfiguration)
			c, err := NewEnclaveHTTPClient(ctx, "enclave.example", RepoPin{Repo: "org/repo"}, &EnclaveOptions{FetchAttestation: tc.attestation})
			require.Nil(t, c)
			require.ErrorIs(t, err, ErrConfiguration)
			r, err := NewRouterHTTPClient(ctx, &RouterOptions{FetchAttestation: tc.attestation})
			require.Nil(t, r)
			require.ErrorIs(t, err, ErrConfiguration)
			r, err = NewRouterHTTPClient(ctx, &RouterOptions{FetchRouterList: tc.list})
			require.Nil(t, r)
			require.ErrorIs(t, err, ErrConfiguration)
		})
	}
	for _, url := range []string{"https://app.example", "https://app.example/tinfoil/", "http://localhost:8080/tinfoil", "http://127.0.0.1:8080", "http://[::1]:8080"} {
		_, err := unverifiedEnclaveHTTPClient("enclave.example", RepoPin{Repo: "org/repo"}, &EnclaveOptions{FetchAttestation: AttestationRelay{URL: url}})
		require.NoError(t, err, url)
		_, err = NewRouterHTTPClient(ctx, &RouterOptions{FetchAttestation: &AttestationRelay{URL: url}, FetchRouterList: RouterListRelay{URL: url}})
		require.ErrorIs(t, err, context.Canceled, "%s passes the checks and reaches discovery", url)
	}
}

func TestAttestationRelayRequest(t *testing.T) {
	requests := make(chan *http.Request, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r.Clone(context.Background())
		_, _ = io.WriteString(w, "document")
	}))
	t.Cleanup(server.Close)
	nonce := make([]byte, document.NonceSize)
	nonce[0] = 0xAB
	for mount, path := range map[string]string{
		"":          "/.well-known/tinfoil-attestation",
		"/":         "/.well-known/tinfoil-attestation",
		"/tinfoil":  "/tinfoil/.well-known/tinfoil-attestation",
		"/tinfoil/": "/tinfoil/.well-known/tinfoil-attestation",
	} {
		body, err := AttestationRelay{URL: server.URL + mount}.FetchAttestation(t.Context(), "enclave.example:8443", nonce)
		require.NoError(t, err, mount)
		require.Equal(t, "document", string(body))
		r := <-requests
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, path, r.URL.Path, "mounted at %q", mount)
		require.Equal(t, "nonce="+hex.EncodeToString(nonce)+"&enclave=enclave.example%3A8443", r.URL.RawQuery)
		require.Equal(t, sdkinfo.Name, r.Header.Get("Tinfoil-SDK"))
		require.Equal(t, sdkinfo.Version(), r.Header.Get("Tinfoil-SDK-Version"))
	}
}

func TestAttestationRelayAppliesTheFetchRules(t *testing.T) {
	var status int
	var location string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if location != "" {
			http.Redirect(w, r, location, http.StatusFound)
			return
		}
		w.WriteHeader(status)
	}))
	t.Cleanup(server.Close)
	relay := AttestationRelay{URL: server.URL}
	nonce := make([]byte, document.NonceSize)

	status = http.StatusBadGateway
	_, err := relay.FetchAttestation(t.Context(), "enclave.example", nonce)
	require.ErrorIs(t, err, ErrNetwork, "an error status")

	status, location = http.StatusOK, server.URL+"/elsewhere"
	_, err = relay.FetchAttestation(t.Context(), "enclave.example", nonce)
	require.ErrorIs(t, err, ErrNetwork)
	require.ErrorContains(t, err, "refusing redirect to non-HTTPS URL")

	// An AttestationRelay that a caller embeds in its own type isn't checked
	// at construction, so the relay checks its URL itself.
	_, err = AttestationRelay{URL: "http://app.example"}.FetchAttestation(t.Context(), "enclave.example", nonce)
	require.ErrorIs(t, err, ErrConfiguration)
}

func TestRouterListRelayRequest(t *testing.T) {
	var body string
	paths := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths <- r.URL.RequestURI()
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(server.Close)
	for mount, path := range map[string]string{"": "/routers", "/": "/routers", "/tinfoil": "/tinfoil/routers", "/tinfoil/": "/tinfoil/routers"} {
		body = `["a.example","b.example"]`
		routers, err := RouterListRelay{URL: server.URL + mount}.FetchRouterList(t.Context())
		require.NoError(t, err)
		require.Equal(t, []string{"a.example", "b.example"}, routers)
		require.Equal(t, path, <-paths, "mounted at %q", mount)
	}
	for _, bad := range []string{`{"routers":[]}`, `["a.example",1]`, `not json`, `["` + strings.Repeat("a", 32<<20) + `"]`} {
		body = bad
		_, err := RouterListRelay{URL: server.URL}.FetchRouterList(t.Context())
		require.ErrorIs(t, err, ErrNetwork, "%.20s", bad)
		<-paths
	}
}

// A relayed list goes through discovery as Tinfoil's list does.
func TestRouterClientDiscoversFromARelayedList(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `["a.example"]`)
	}))
	t.Cleanup(server.Close)
	fetcher := &recordingFetcher{result: func(context.Context, string, []byte) ([]byte, error) { return nil, errors.New("unreachable") }}
	_, err := NewRouterHTTPClient(t.Context(), &RouterOptions{FetchAttestation: fetcher, FetchRouterList: RouterListRelay{URL: server.URL}})
	require.ErrorIs(t, err, ErrNetwork)
	require.Equal(t, []string{"a.example", "inference.tinfoil.sh", "inference.tinfoil.sh"}, fetcher.hosts(), "the listed router, then the fallback with its retry")
}

func TestAttestationFetcherServesEveryVerification(t *testing.T) {
	refuseDirectFetches(t)
	synctest.Test(t, func(t *testing.T) {
		fetcher := &recordingFetcher{result: func(context.Context, string, []byte) ([]byte, error) { return []byte("{}"), nil }}
		_, err := NewEnclaveHTTPClient(context.Background(), "enclave.example", RepoPin{Repo: "org/repo"}, &EnclaveOptions{FetchAttestation: fetcher})
		require.ErrorIs(t, err, ErrAttestation, "the document is verified")
		require.NotErrorIs(t, err, ErrNetwork)
		require.Equal(t, []string{"enclave.example", "enclave.example"}, fetcher.hosts(), "initial verification, with its retry")
		require.Len(t, fetcher.calls[0].nonce, document.NonceSize)
		require.NotEqual(t, fetcher.calls[0].nonce, fetcher.calls[1].nonce, "each attempt has a fresh nonce")

		c, err := unverifiedEnclaveHTTPClient("enclave.example", RepoPin{Repo: "org/repo"}, &EnclaveOptions{FetchAttestation: AttestationFetcherFunc(fetcher.FetchAttestation)})
		require.NoError(t, err)
		_, err = c.Reverify(context.Background())
		require.ErrorIs(t, err, ErrAttestation)
		_, err = c.EnsureVerified(context.Background())
		require.ErrorIs(t, err, ErrAttestation)
		require.Len(t, fetcher.hosts(), 6, "re-verification uses the fetcher too")

		fetcher.calls = nil
		_, err = NewRouterHTTPClient(context.Background(), &RouterOptions{
			FetchAttestation: fetcher,
			FetchRouterList:  RouterListFetcherFunc(func(context.Context) ([]string, error) { return []string{"a.example", "b.example"}, nil }),
		})
		require.ErrorIs(t, err, ErrAttestation)
		hosts := fetcher.hosts()
		require.Len(t, hosts, 4)
		require.ElementsMatch(t, []string{"a.example", "b.example"}, hosts[:2], "discovery's routers, in shuffled order")
		require.Equal(t, []string{"inference.tinfoil.sh", "inference.tinfoil.sh"}, hosts[2:], "then the fallback")
	})
}

func TestAttestationFetcherErrors(t *testing.T) {
	refuseDirectFetches(t)
	cause := errors.New("relay unavailable")
	for name, tc := range map[string]struct {
		err   error
		is    error
		calls int
	}{
		"plain error":         {cause, ErrNetwork, 2},
		"network error":       {fetchErr(ErrNetwork, cause), ErrNetwork, 2},
		"attestation error":   {fetchErr(ErrAttestation, cause), ErrAttestation, 2},
		"configuration error": {fetchErr(ErrConfiguration, cause), ErrConfiguration, 1},
	} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				fetcher := &recordingFetcher{result: func(context.Context, string, []byte) ([]byte, error) { return nil, tc.err }}
				_, err := NewEnclaveHTTPClient(context.Background(), "enclave.example", RepoPin{Repo: "org/repo"}, &EnclaveOptions{FetchAttestation: fetcher})
				require.ErrorIs(t, err, tc.is)
				require.ErrorIs(t, err, cause)
				for _, other := range []error{ErrNetwork, ErrAttestation, ErrConfiguration} {
					if other != tc.is {
						require.NotErrorIs(t, err, other, "an SDK category is kept, not wrapped")
					}
				}
				require.Len(t, fetcher.calls, tc.calls, "a configuration error isn't retried")
			})
		})
	}
}

// fetchErr returns cause in the SDK category, as a caller's fetcher that
// calls a relay would.
func fetchErr(category, cause error) error {
	switch category {
	case ErrNetwork:
		return errs.Network(cause)
	case ErrAttestation:
		return errs.Attestation(cause)
	default:
		return errs.Configuration(cause)
	}
}

func TestCancellationPassesThroughAFetcher(t *testing.T) {
	refuseDirectFetches(t)
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		fetcher := &recordingFetcher{result: func(ctx context.Context, _ string, _ []byte) ([]byte, error) {
			select {
			case <-release:
				return nil, errors.New("released")
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			_, err := NewEnclaveHTTPClient(ctx, "enclave.example", RepoPin{Repo: "org/repo"}, &EnclaveOptions{FetchAttestation: fetcher})
			done <- err
		}()
		synctest.Wait()
		cancel()
		err := <-done
		require.Equal(t, context.Canceled, err, "the caller's cancellation, unwrapped")

		ctx, cancel = context.WithCancel(context.Background())
		go func() {
			_, err := NewRouterHTTPClient(ctx, &RouterOptions{
				FetchAttestation: fetcher,
				FetchRouterList: RouterListFetcherFunc(func(ctx context.Context) ([]string, error) {
					<-ctx.Done()
					return nil, ctx.Err()
				}),
			})
			done <- err
		}()
		synctest.Wait()
		cancel()
		require.Equal(t, context.Canceled, <-done, "discovery fails with the caller's cancellation, not a fallback")
		close(release)
		time.Sleep(time.Minute) // let the abandoned verifications finish their retries
	})
}

func TestARelayPointerIsCopied(t *testing.T) {
	var hosts []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hosts = append(hosts, r.URL.Query().Get("enclave"))
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(server.Close)
	relay := &AttestationRelay{URL: server.URL}
	c, err := unverifiedEnclaveHTTPClient("enclave.example", RepoPin{Repo: "org/repo"}, &EnclaveOptions{FetchAttestation: relay})
	require.NoError(t, err)
	relay.URL = "http://app.example"
	_, err = c.attestedClient.keyed.VerifyOnce(t.Context())
	require.ErrorIs(t, err, ErrNetwork)
	require.Equal(t, []string{"enclave.example"}, hosts, "the client keeps the relay that it checked")
}

func TestGatewayRelaysAttestationThroughItsOrigin(t *testing.T) {
	var mu sync.Mutex
	var fetched []string
	original := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = original })
	synctest.Test(t, func(t *testing.T) {
		http.DefaultTransport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
			mu.Lock()
			fetched = append(fetched, req.URL.Scheme+"://"+req.URL.Host+req.URL.Path+" enclave="+req.URL.Query().Get("enclave"))
			mu.Unlock()
			return nil, errors.New("no network in this test")
		})
		gw, err := NewGatewayHTTPClient(context.Background(), &GatewayOptions{
			URL:     "https://gateway.example/v1/",
			Catalog: func() Catalog { return Catalog{"m": {Repo: "tinfoilsh/m", Hosts: []string{"replica.example"}}} },
		})
		require.NoError(t, err)
		_, err = gw.EnsureVerified(context.Background(), "m")
		require.ErrorIs(t, err, ErrNetwork)
		require.Contains(t, fetched, "https://gateway.example/.well-known/tinfoil-attestation enclave=replica.example")
	})
}

func TestLiveAttestationFetcher(t *testing.T) {
	testutil.RequireLive(t, "TINFOIL_ENCLAVE", "TINFOIL_REPO")
	host, trust := os.Getenv("TINFOIL_ENCLAVE"), RepoPin{Repo: os.Getenv("TINFOIL_REPO")}
	direct := &recordingFetcher{result: fetch.Document}
	c, err := NewEnclaveHTTPClient(t.Context(), host, trust, &EnclaveOptions{FetchAttestation: direct})
	require.NoError(t, err, "a document that a fetcher delivers verifies")
	_, err = c.Reverify(t.Context())
	require.NoError(t, err)
	require.Equal(t, []string{host, host}, direct.hosts())

	wrongNonce := AttestationFetcherFunc(func(ctx context.Context, host string, nonce []byte) ([]byte, error) {
		other, err := document.RandomNonce()
		if err != nil {
			return nil, err
		}
		return fetch.Document(ctx, host, other)
	})
	_, err = NewEnclaveHTTPClient(t.Context(), host, trust, &EnclaveOptions{FetchAttestation: wrongNonce})
	require.ErrorIs(t, err, ErrAttestation, "a document for another nonce is rejected")
}

func TestLiveRouterClientWithFetchers(t *testing.T) {
	testutil.RequireLive(t)
	var listed []string
	direct := &recordingFetcher{result: fetch.Document}
	c, err := NewRouterHTTPClient(t.Context(), &RouterOptions{
		FetchAttestation: direct,
		FetchRouterList: RouterListFetcherFunc(func(ctx context.Context) ([]string, error) {
			routers, err := (RouterListRelay{URL: "https://atc.tinfoil.sh"}).FetchRouterList(ctx)
			listed = routers
			return routers, err
		}),
	})
	require.NoError(t, err)
	require.NotEmpty(t, listed, "ATC serves the relay protocol's list path")
	require.Contains(t, direct.hosts(), c.Enclave(), "the chosen router was verified through the fetcher")
}

// An attestation document doesn't name its host, so a document of another
// router verifies; the channel binding then refuses the host that the client
// connects to.
func TestLiveAnotherEnclavesDocumentFailsAtChannelBinding(t *testing.T) {
	testutil.RequireLive(t)
	routers, err := RouterListRelay{URL: "https://atc.tinfoil.sh"}.FetchRouterList(t.Context())
	require.NoError(t, err)
	if len(routers) < 2 {
		t.Skip("needs two routers")
	}
	other := AttestationFetcherFunc(func(ctx context.Context, _ string, nonce []byte) ([]byte, error) {
		return fetch.Document(ctx, routers[1], nonce)
	})
	c, err := NewEnclaveHTTPClient(t.Context(), routers[0], RepoPin{Repo: "tinfoilsh/confidential-model-router"}, &EnclaveOptions{FetchAttestation: other})
	require.NoError(t, err, "the document verifies")
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, c.BaseURL()+"v1/models", nil)
	require.NoError(t, err)
	_, err = c.Do(req)
	require.ErrorIs(t, err, ErrAttestation, "the TLS key doesn't match the document")
}
