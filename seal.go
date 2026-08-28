package tinfoil

import (
	"fmt"
	"net/http"
	"sync"

	log "github.com/sirupsen/logrus"
	"github.com/tinfoilsh/tinfoil-go/verifier/client"
)

// seal reconciles EHBP, which seals a body to one enclave, with a gateway that picks the replica.
//
// Every request names the enclave it is sealed to. A gateway that routed elsewhere answers 421
// before forwarding the body, naming the enclave it picked; the client attests that enclave,
// re-seals, and retries. The gateway can only name a host, and a host that does not attest against
// the pinned repo is never sealed to.
const (
	// sealHeader names the enclave a body is sealed to on the way out, and the one routing picked on the way back.
	sealHeader = "X-Tinfoil-Seal"

	// maxSealRedirects bounds re-sealing: routing may legitimately move between the 421 and the retry.
	maxSealRedirects = 3
)

// sealFollowingTransport keeps the sealing transport pointed at the enclave the gateway routes to.
type sealFollowingTransport struct {
	// build attests an enclave and returns a sealing transport bound to its HPKE key.
	build func(enclave string) (*ehbpReVerifyingTransport, error)

	mu      sync.RWMutex
	enclave string
	current *ehbpReVerifyingTransport
	// known holds every enclave already attested, so bouncing between replicas attests each once.
	known map[string]*ehbpReVerifyingTransport

	// followMu serializes re-sealing so concurrent requests seeing the same redirect attest once.
	followMu sync.Mutex
}

func newSealFollowingTransport(enclave string, initial *ehbpReVerifyingTransport, build func(string) (*ehbpReVerifyingTransport, error)) *sealFollowingTransport {
	return &sealFollowingTransport{
		build:   build,
		enclave: enclave,
		current: initial,
		known:   map[string]*ehbpReVerifyingTransport{enclave: initial},
	}
}

func (t *sealFollowingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	for attempt := 0; ; attempt++ {
		enclave, current := t.active()
		out := req.Clone(req.Context())
		out.Header.Set(sealHeader, enclave)

		resp, err := current.RoundTrip(out)
		if err != nil {
			return resp, err
		}
		// Only a response naming another enclave is a redirect; a bare 421 is the enclave's own answer.
		target := resp.Header.Get(sealHeader)
		if resp.StatusCode != http.StatusMisdirectedRequest || target == "" || target == enclave {
			return resp, nil
		}
		resp.Body.Close()

		if attempt == maxSealRedirects {
			return nil, fmt.Errorf("gateway kept routing away from the enclave the request was sealed to (last: %q)", target)
		}
		if err := t.follow(target); err != nil {
			return nil, fmt.Errorf("gateway routed to enclave %q, which failed verification: %w", target, err)
		}
		if req, err = resetRequestBody(req); err != nil {
			return nil, err
		}
	}
}

func (t *sealFollowingTransport) follow(enclave string) error {
	t.followMu.Lock()
	defer t.followMu.Unlock()

	if active, _ := t.active(); active == enclave {
		// A concurrent request already moved us here.
		return nil
	}
	t.mu.RLock()
	next := t.known[enclave]
	t.mu.RUnlock()

	if next == nil {
		built, err := t.build(enclave)
		if err != nil {
			return err
		}
		next = built
		enclave = next.activeEnclave()
		log.Infof("Gateway routed to enclave %s; verified it and re-sealing there", enclave)
	}

	t.mu.Lock()
	t.enclave, t.current, t.known[enclave] = enclave, next, next
	t.mu.Unlock()
	return nil
}

func (t *sealFollowingTransport) active() (string, *ehbpReVerifyingTransport) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.enclave, t.current
}

func (t *sealFollowingTransport) verifyAndReplace() (*client.GroundTruth, error) {
	_, current := t.active()
	return current.verifyAndReplace()
}

func (t *sealFollowingTransport) verificationDocument() *client.VerificationDocument {
	_, current := t.active()
	return current.verificationDocument()
}

func (t *sealFollowingTransport) activeEnclave() string {
	enclave, _ := t.active()
	return enclave
}
