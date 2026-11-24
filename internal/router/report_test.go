package router

import (
	"context"
	"errors"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/tinfoilsh/tinfoil-go/internal/enclave"
	"github.com/tinfoilsh/tinfoil-go/internal/errs"
	"github.com/tinfoilsh/tinfoil-go/internal/transport"
	"github.com/tinfoilsh/tinfoil-go/internal/verifytest"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/document"
)

type attempt struct {
	host   string
	report *verify.VerificationReport
	err    error
}

type attempts struct {
	mu   sync.Mutex
	seen []attempt
}

func (a *attempts) record(host string, report *verify.VerificationReport, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.seen = append(a.seen, attempt{host, report, err})
}

func (a *attempts) hosts() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var hosts []string
	for _, s := range a.seen {
		hosts = append(hosts, s.host)
	}
	return hosts
}

// Discovery reports the attempt of every router that it tries, and of the
// fallback, each with its own host.
func TestDiscoveryReportsEveryRouterTried(t *testing.T) {
	keepOrder(t)
	synctest.Test(t, func(t *testing.T) {
		seen := &attempts{}
		unreachable := errors.New("unreachable")
		h, err := Discover(context.Background(), Options{
			NewTransport:   newTLS,
			OnVerification: seen.record,
			List: func(context.Context) ([]string, error) {
				return []string{"a.example", "b.example"}, nil
			},
			FetchAttestation: func(context.Context, string, []byte) ([]byte, error) { return nil, unreachable },
		})
		require.NoError(t, err)
		require.Equal(t, []string{"a.example", "b.example"}, seen.hosts(), "the fallback is verified on first use")
		_, err = h.EnsureVerified(context.Background())
		require.ErrorIs(t, err, unreachable)
		// The fallback's verification has one retry.
		require.Equal(t, []string{"a.example", "b.example", "inference.tinfoil.sh", "inference.tinfoil.sh"}, seen.hosts())
		last, lastErr := h.LastVerification()
		require.Nil(t, last)
		require.ErrorIs(t, lastErr, errs.ErrNetwork)
	})
}

// A router that fails verification is reported and skipped; the chosen one is
// reported too, and the client's last verification describes it.
func TestDiscoveryReportsTheSkippedAndTheChosenRouter(t *testing.T) {
	keepOrder(t)
	seen := &attempts{}
	rejected := errs.Attestation(verifytest.Rejected("report signature is invalid"))
	h, err := Discover(context.Background(), Options{
		OnVerification: seen.record,
		// The test replaces each router's verification, keeping its host
		// and the callback that discovery gave it.
		NewTransport: func(e *enclave.Enclave) *transport.Transport {
			return transport.TLS(enclave.NewForTest(e.Host(), func() (*verify.VerificationReport, error) {
				if e.Host() == "bad.example" {
					return nil, rejected
				}
				return verifytest.NewReport(verifytest.Fields{CodeTag: e.Host(), FreshnessExpiresAt: time.Now().Add(time.Hour), CryptoMaterial: []document.CryptoMaterialItem{
					{ID: document.CryptoMaterialIDTLS, Format: document.KeySPKIFPSHA256V1Format, Data: "aa"},
				}}), nil
			}, func(_ string, r *verify.VerificationReport, err error) { e.Notify(r, err) }))
		},
		List: func(context.Context) ([]string, error) { return []string{"bad.example", "good.example"}, nil },
	})
	require.NoError(t, err)
	require.Equal(t, "good.example", h.Enclave().Host())
	require.Equal(t, []string{"bad.example", "good.example"}, seen.hosts())
	require.ErrorIs(t, seen.seen[0].err, rejected)
	require.Equal(t, "good.example", seen.seen[1].report.VerifiedFacts.CodeTag())
	last, err := h.LastVerification()
	require.NoError(t, err)
	require.Equal(t, "good.example", last.VerifiedFacts.CodeTag())
}
