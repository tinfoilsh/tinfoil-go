package tinfoil

import (
	"fmt"
	"io"
	"net/http"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/verifier/client"
)

// sealingStub stands in for the EHBP transport of one enclave, answering as the gateway
// would for a body sealed somewhere other than where routing sent it.
type sealingStub struct {
	enclave string
	routeTo string // when set, answers 421 naming this enclave instead
	mu      sync.Mutex
	calls   int
	bodies  []string
}

func (s *sealingStub) transport() *ehbpReVerifyingTransport {
	return &ehbpReVerifyingTransport{secureClient: client.NewSecureClient(s.enclave, defaultConfigRepo), transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		s.mu.Lock()
		s.calls++
		s.bodies = append(s.bodies, string(body))
		s.mu.Unlock()
		if s.routeTo != "" && req.Header.Get(sealHeader) != s.routeTo {
			resp := newResponse(http.StatusMisdirectedRequest, "re-seal")
			resp.Header.Set(sealHeader, s.routeTo)
			return resp, nil
		}
		return newResponse(http.StatusOK, "ok from "+s.enclave), nil
	})}
}

// sealFollower wires a transport over the given stubs and reports how many times each was attested.
func sealFollower(t *testing.T, start string, stubs map[string]*sealingStub) (*sealFollowingTransport, *map[string]int) {
	t.Helper()
	attested := map[string]int{start: 1}
	return newSealFollowingTransport(start, stubs[start].transport(), func(enclave string) (*ehbpReVerifyingTransport, error) {
		stub, ok := stubs[enclave]
		if !ok {
			return nil, fmt.Errorf("no such enclave: %s", enclave)
		}
		attested[enclave]++
		return stub.transport(), nil
	}), &attested
}

func sealRequest(t *testing.T, rt http.RoundTripper) (*http.Response, error) {
	t.Helper()
	return rt.RoundTrip(postJSONRequest(t, "https://gateway.example.com"+chatPath, `{"model":"m"}`))
}

func TestSealFollowsTheGatewaysRedirect(t *testing.T) {
	// a is where the client sealed; the gateway routes this prompt to b.
	stubs := map[string]*sealingStub{
		"a.example.com": {enclave: "a.example.com", routeTo: "b.example.com"},
		"b.example.com": {enclave: "b.example.com"},
	}
	rt, attested := sealFollower(t, "a.example.com", stubs)

	for range 3 {
		resp, err := sealRequest(t, rt)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Equal(t, "ok from b.example.com", string(body))
	}

	require.Equal(t, "b.example.com", rt.activeEnclave())
	require.Equal(t, `{"model":"m"}`, stubs["b.example.com"].bodies[0])
	// Only the first request pays for a redirect; the rest seal to b directly.
	require.Equal(t, 1, (*attested)["b.example.com"])
	require.Equal(t, 1, stubs["a.example.com"].calls)
	require.Equal(t, 3, stubs["b.example.com"].calls)
}

// An enclave the gateway names but that does not attest is never sealed to.
func TestSealRefusesAnUnverifiableEnclave(t *testing.T) {
	stubs := map[string]*sealingStub{"a.example.com": {enclave: "a.example.com", routeTo: "evil.example.com"}}
	rt, _ := sealFollower(t, "a.example.com", stubs)

	_, err := sealRequest(t, rt)
	require.ErrorContains(t, err, "evil.example.com")
	require.ErrorContains(t, err, "failed verification")
	require.Equal(t, "a.example.com", rt.activeEnclave())
}

func TestSealGivesUpOnAGatewayThatNeverConverges(t *testing.T) {
	pingpong := map[string]*sealingStub{
		"a.example.com": {enclave: "a.example.com", routeTo: "b.example.com"},
		"b.example.com": {enclave: "b.example.com", routeTo: "a.example.com"},
	}
	rt, _ := sealFollower(t, "a.example.com", pingpong)

	_, err := sealRequest(t, rt)
	require.ErrorContains(t, err, "kept routing away")
	require.Equal(t, maxSealRedirects+1, pingpong["a.example.com"].calls+pingpong["b.example.com"].calls)
}

// Only a 421 naming another enclave re-seals: a bare 421 is the enclave's own answer, and 422 belongs to EHBP.
func TestSealLeavesOrdinaryErrorsAlone(t *testing.T) {
	for _, answer := range []struct {
		name   string
		status int
		seal   string
	}{
		{"bare misdirect", http.StatusMisdirectedRequest, ""},
		{"misdirect naming this enclave", http.StatusMisdirectedRequest, "a.example.com"},
		{"unprocessable entity naming an enclave", http.StatusUnprocessableEntity, "b.example.com"},
	} {
		t.Run(answer.name, func(t *testing.T) {
			rt := newSealFollowingTransport("a.example.com", &ehbpReVerifyingTransport{
				transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
					resp := newResponse(answer.status, "bad request")
					if answer.seal != "" {
						resp.Header.Set(sealHeader, answer.seal)
					}
					return resp, nil
				}),
			}, func(string) (*ehbpReVerifyingTransport, error) {
				t.Fatal("must not re-seal without another enclave to seal to")
				return nil, nil
			})

			resp, err := sealRequest(t, rt)
			require.NoError(t, err)
			require.Equal(t, answer.status, resp.StatusCode)
		})
	}
}

func TestSealFollowsOnceUnderConcurrency(t *testing.T) {
	var mu sync.Mutex
	attempts := 0
	stub := &sealingStub{enclave: "b.example.com"}
	rt := newSealFollowingTransport("a.example.com", (&sealingStub{
		enclave: "a.example.com", routeTo: "b.example.com",
	}).transport(), func(string) (*ehbpReVerifyingTransport, error) {
		mu.Lock()
		attempts++
		mu.Unlock()
		return stub.transport(), nil
	})

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := sealRequest(t, rt)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode)
		}()
	}
	wg.Wait()
	require.Equal(t, 1, attempts)
	require.Equal(t, "b.example.com", rt.activeEnclave())
}

// Sealing follows the enclave that actually attested, not the name the gateway put on the wire.
func TestSealRecordsTheEnclaveItAttested(t *testing.T) {
	attested := &sealingStub{enclave: "c.example.com", routeTo: "c.example.com"}
	rt := newSealFollowingTransport("a.example.com",
		(&sealingStub{enclave: "a.example.com", routeTo: "b.example.com"}).transport(),
		func(string) (*ehbpReVerifyingTransport, error) { return attested.transport(), nil })

	resp, err := sealRequest(t, rt)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "c.example.com", rt.activeEnclave())
	require.Equal(t, 1, attested.calls)
}

// The whole stack: the cache secret goes into the sealed body, and a redirect re-seals that same body.
func TestSealedRequestStackFollowsARedirect(t *testing.T) {
	stubs := map[string]*sealingStub{
		"a.example.com": {enclave: "a.example.com", routeTo: "b.example.com"},
		"b.example.com": {enclave: "b.example.com"},
	}
	seal, _ := sealFollower(t, "a.example.com", stubs)
	stack := sealedRequestTransport(seal, TransportEHBP, "s1")

	resp, err := stack.RoundTrip(postJSONRequest(t, "https://gateway.example.com"+chatPath,
		`{"model":"m","messages":[{"role":"user","content":"hi"}]}`))
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	require.Len(t, stubs["b.example.com"].bodies, 1)
	require.Contains(t, stubs["b.example.com"].bodies[0], `"user_cache_secret":"s1"`)
	require.Equal(t, stubs["a.example.com"].bodies[0], stubs["b.example.com"].bodies[0],
		"the re-sealed body must be the one that was sealed the first time")
}
