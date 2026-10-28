// Package enclave manages an attested enclave's verification state. A Handle
// fetches and verifies one enclave's attestation and keeps the result until it
// expires or is invalidated; package transport ties HTTP traffic to the keys
// it endorses.
package enclave

import (
	"sync"

	"github.com/tinfoilsh/tinfoil-go/verify"
)

// Handle is the client-side handle for one attested enclave. It verifies the
// enclave's attestation on first use, and again when the result expires or is
// invalidated. Transports built on it bind traffic to the keys of the State it
// ensures is valid; they all share one verification and one refresh.
type Handle struct {
	enclave, repo, relay string
	// verifier is the immutable verification policy, shareable across handles.
	verifier *verify.Verifier
	// check is the caller's VerificationCheck, or nil.
	check func(v *verify.Verification) error

	stateMu    sync.RWMutex
	state      *State
	generation uint64
	refreshing *verificationCall
	verify     func() (*verify.Verification, error)
}

// Config describes the enclave a Handle verifies.
type Config struct {
	// Host is the enclave, a host with an optional port.
	Host string
	// Relay, when set, is a host that fetches attestation from the enclave on
	// the client's behalf.
	Relay string
	// Repo pins a repository or registry project,
	// org/project[@revision][@sha256:digest].
	Repo string
	// Verifier is the policy, which several handles can share; nil selects the
	// defaults, which require Repo.
	Verifier *verify.Verifier
	// VerificationCheck, when set, is called with each verification that
	// passes Verifier, before the handle keeps it. An error rejects the
	// verification without a retry.
	VerificationCheck func(v *verify.Verification) error
}

// NewTestHandle returns a handle for host that starts from initial, unless it
// is nil, and verifies by calling fetch instead of fetching and verifying a
// document. It is for the tests of packages built on enclave.
func NewTestHandle(host string, initial *verify.Verification, fetch func() (*verify.Verification, error)) *Handle {
	s := &Handle{enclave: host, verify: fetch}
	if initial != nil {
		s.state = &State{verification: initial}
	}
	return s
}

// NewHandle checks c.Repo against the verifier's rules for a repository pin
// and does no network I/O; the enclave is verified on first use.
func NewHandle(c Config) (*Handle, error) {
	v := c.Verifier
	if v == nil {
		var err error
		if v, err = verify.NewVerifier(); err != nil {
			return nil, fromVerify(err)
		}
	}
	if err := v.CheckRepoVerifiability(c.Repo); err != nil {
		return nil, fromVerify(err)
	}
	return &Handle{enclave: c.Host, repo: c.Repo, relay: c.Relay, verifier: v, check: c.VerificationCheck}, nil
}

// Enclave returns the enclave host.
func (s *Handle) Enclave() string {
	return s.enclave
}

// Repo returns the trusted repository or registry reference, including version and digest pins.
func (s *Handle) Repo() string {
	return s.repo
}

// Verifier returns the verification policy, which several handles can share.
func (s *Handle) Verifier() *verify.Verifier {
	return s.verifier
}

// Current returns the last successful verification without checking it, or
// nil before the first. It may have expired or been invalidated; use
// EnsureVerified for one that is valid.
func (s *Handle) Current() *State {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	return s.state
}
