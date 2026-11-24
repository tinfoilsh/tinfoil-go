package gateway

import (
	"context"
	"errors"
	"strconv"
	"strings"
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

// replicaReport is a fresh report with the code tag tag.
func replicaReport(tag string) *verify.VerificationReport {
	return verifytest.NewReport(verifytest.Fields{CodeTag: tag, FreshnessExpiresAt: time.Now().Add(time.Hour), CryptoMaterial: []document.CryptoMaterialItem{
		{ID: document.CryptoMaterialIDTLS, Format: document.KeySPKIFPSHA256V1Format, Data: "aa"},
		{ID: document.CryptoMaterialIDHPKE, Format: document.KeyX25519HPKEV1Format, Data: strings.Repeat("11", 32)},
	}})
}

// reverifyGateway serves sealTestModel from two replicas, in the model's
// order first and second, verified through real transports. Each fetch of a
// replica's document returns a fresh report tagged "<host>#<n>", unless
// fail returns an error for that host and fetch number.
type reverifyGateway struct {
	*Transport
	first, second string
	mu            sync.Mutex
	fetches       map[string]int
	fail          func(host string, n int) error
}

func newReverifyGateway() *reverifyGateway {
	hosts := []string{"a.example", "b.example"}
	order := rank(hosts, sealTestModel, "")
	g := &reverifyGateway{first: order[0], second: order[1], fetches: map[string]int{}, fail: func(string, int) error { return nil }}
	g.Transport = &Transport{
		policy:  sealTestPolicy,
		catalog: staticCatalog(Catalog{sealTestModel: {Repo: "tinfoilsh/test", Hosts: hosts}}),
		build: func(r replica) (*verifiedReplicaTransport, error) {
			e := enclave.NewForTest(r.host, func() (*verify.VerificationReport, error) {
				g.mu.Lock()
				g.fetches[r.host]++
				n := g.fetches[r.host]
				g.mu.Unlock()
				if err := g.fail(r.host, n); err != nil {
					return nil, err
				}
				return replicaReport(r.host + "#" + strconv.Itoa(n)), nil
			}, nil)
			keyed := transport.WithEHBP(nil, e)
			return newReplicaTransport(keyed, keyed), nil
		},
	}
	return g
}

func (g *reverifyGateway) fetchesOf(host string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.fetches[host]
}

func (g *reverifyGateway) entry(t *testing.T, host string) ReplicaVerification {
	t.Helper()
	for _, e := range g.Replicas() {
		if e.Host == host {
			return e
		}
	}
	t.Fatalf("no entry for %s", host)
	return ReplicaVerification{}
}

func tag(r *verify.VerificationReport) string {
	if r == nil {
		return ""
	}
	return r.VerifiedFacts.CodeTag()
}

func TestGatewayReverifyVerifiesTheReplicaInUseAgain(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g := newReverifyGateway()
		ensured, err := g.EnsureVerified(context.Background(), sealTestModel)
		require.NoError(t, err)
		require.Equal(t, g.first+"#1", tag(ensured))

		reverified, err := g.Reverify(context.Background(), sealTestModel)
		require.NoError(t, err)
		require.Equal(t, g.first+"#2", tag(reverified), "the valid verification is verified again")
		require.Zero(t, g.fetchesOf(g.second), "no other replica is verified")

		e := g.entry(t, g.first)
		require.Equal(t, reverified, e.Current)
		requireReportHost(t, g.first, e.Current)
		require.Equal(t, reverified, e.LastAttempt.Report)
		require.NoError(t, e.LastAttempt.Err)
		require.Len(t, g.Replicas(), 1)

		again, err := g.EnsureVerified(context.Background(), sealTestModel)
		require.NoError(t, err)
		require.Equal(t, reverified, again)
	})
}

// A failure that keeps the replica's verification is Reverify's outcome:
// requests for the model still go to that replica.
func TestGatewayReverifyReportsAFailureThatKeepsTheVerification(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g := newReverifyGateway()
		ensured, err := g.EnsureVerified(context.Background(), sealTestModel)
		require.NoError(t, err)
		unreachable := errs.Network(errors.New("attestation source unavailable"))
		g.fail = func(host string, n int) error {
			if host == g.first && n > 1 {
				return unreachable
			}
			return nil
		}

		_, err = g.Reverify(context.Background(), sealTestModel)
		require.ErrorIs(t, err, errs.ErrNetwork)
		require.Zero(t, g.fetchesOf(g.second), "the next replica is not tried")

		e := g.entry(t, g.first)
		require.Equal(t, ensured, e.Current, "the replica's verification is still current")
		require.Nil(t, e.LastAttempt.Report)
		require.ErrorIs(t, e.LastAttempt.Err, errs.ErrNetwork, "its last attempt is the failure")

		again, err := g.EnsureVerified(context.Background(), sealTestModel)
		require.NoError(t, err)
		require.Equal(t, ensured, again)
	})
}

// An attestation failure discards the replica's verification, so Reverify
// moves on to the replica that EnsureVerified then returns.
func TestGatewayReverifyMovesOnAfterADiscard(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g := newReverifyGateway()
		_, err := g.EnsureVerified(context.Background(), sealTestModel)
		require.NoError(t, err)
		g.fail = func(host string, n int) error {
			if host == g.first && n > 1 {
				return errs.Attestation(errors.New("the document fails verification"))
			}
			return nil
		}

		reverified, err := g.Reverify(context.Background(), sealTestModel)
		require.NoError(t, err)
		require.Equal(t, g.second+"#1", tag(reverified))

		discarded := g.entry(t, g.first)
		require.Nil(t, discarded.Current, "the failure discarded the replica's verification")
		require.ErrorIs(t, discarded.LastAttempt.Err, errs.ErrAttestation)
		next := g.entry(t, g.second)
		require.Equal(t, reverified, next.Current)
		require.Equal(t, reverified, next.LastAttempt.Report)

		fetches := g.fetchesOf(g.first)
		again, err := g.EnsureVerified(context.Background(), sealTestModel)
		require.NoError(t, err)
		require.Equal(t, reverified, again, "EnsureVerified returns the same replica")
		require.Greater(t, g.fetchesOf(g.first), fetches, "after it tries the first replica again")
	})
}

func TestGatewayReverifyRefusesAnUnpinnedModel(t *testing.T) {
	g := newReverifyGateway()
	_, err := g.Reverify(context.Background(), "unpinned")
	require.ErrorIs(t, err, errs.ErrConfiguration)
	require.Empty(t, g.Replicas())
}

// A replica's Current follows its own verification's freshness.
func TestGatewayReplicaCurrentExpires(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g := newReverifyGateway()
		ensured, err := g.EnsureVerified(context.Background(), sealTestModel)
		require.NoError(t, err)
		time.Sleep(2 * time.Hour)
		e := g.entry(t, g.first)
		require.Nil(t, e.Current, "an expired verification is not current")
		require.Equal(t, ensured, e.LastAttempt.Report)
	})
}
