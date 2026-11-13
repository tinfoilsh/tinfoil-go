//go:build tinfoil_conformance

package main

import (
	"encoding/base64"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/tinfoilsh/tinfoil-go/internal/fetch"
	"github.com/tinfoilsh/tinfoil-go/verify/conformance"
	"github.com/tinfoilsh/tinfoil-go/verify/document"
)

// TestLiveVerification fetches a v3 attestation from a real enclave and runs
// the full flow against the embedded production roots (empty anchors) — the
// accepting embedded-root path, on real hardware evidence, provenance, and
// collateral. Opt-in via TINFOIL_LIVE_HOST so ordinary runs stay offline.
//
//	TINFOIL_LIVE_HOST=<enclave> TINFOIL_LIVE_REPO=<owner/name> \
//	  go test -tags tinfoil_conformance -run TestLiveVerification ./cmd/tinfoil-conformance/
func TestLiveVerification(t *testing.T) {
	host := os.Getenv("TINFOIL_LIVE_HOST")
	if host == "" {
		t.Skip("set TINFOIL_LIVE_HOST (and TINFOIL_LIVE_REPO) to verify a live enclave")
	}
	repo := os.Getenv("TINFOIL_LIVE_REPO")

	nonce, err := document.RandomNonce()
	if err != nil {
		t.Fatalf("nonce: %v", err)
	}
	doc, err := fetch.Document(t.Context(), host, "", nonce)
	if err != nil {
		t.Fatalf("fetch from %s: %v", host, err)
	}

	in := conformance.Input{
		SchemaVersion: "1",
		DocumentB64:   base64.StdEncoding.EncodeToString(doc),
		NonceHex:      hex.EncodeToString(nonce),
		Repo:          repo,
	}
	out, code := conformance.Run(conformance.StageVerify, in) // empty anchors => embedded production roots
	if code != conformance.ExitAccepted || out.Outputs == nil {
		reason := "unknown"
		if out.Rejection != nil {
			reason = out.Rejection.Code
		}
		t.Fatalf("live verification rejected (exit %d, %s); host=%s repo=%s", code, reason, host, repo)
	}
	t.Logf("accepted: code_digest=%s enclave=%s", out.Outputs.CodeDigest, out.Outputs.EnclaveMeasurement.Type)

	// Channel binding: the endorsed TLS key must be the key the live enclave
	// actually presents on the wire. This is the whole point of attestation —
	// verifying the document lets the caller trust this connection.
	if fp := out.Outputs.TLSPublicKeyFP; fp != "" {
		live, err := tlsSPKIFingerprint(host)
		if err != nil {
			t.Fatalf("dialing %s for channel binding: %v", host, err)
		}
		if live != fp {
			t.Fatalf("channel binding: live TLS key %s != endorsed %s", live, fp)
		}
		t.Logf("channel bound: live TLS SPKI-fp matches the attested key %s", fp)
	}

	// The same bytes must still verify with the clock pinned to now — the
	// contract a frozen real-frozen fixture relies on, checked on live collateral.
	in.VerificationTimeUnix = time.Now().Unix()
	if _, code := conformance.Run(conformance.StageVerify, in); code != conformance.ExitAccepted {
		t.Fatalf("pinned-time replay of the live document did not accept (exit %d)", code)
	}
}
