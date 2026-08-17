//go:build tinfoil_conformance

package conformance

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/tinfoilsh/tinfoil-go/verifier/envelope"
)

// TestLiveVerification fetches a v3 attestation from a real enclave and runs
// the full flow against the embedded production roots (empty anchors) — the
// accepting embedded-root path, on real hardware evidence, provenance, and
// collateral. Opt-in via TINFOIL_LIVE_HOST so ordinary runs stay offline.
//
//	TINFOIL_LIVE_HOST=<enclave> TINFOIL_LIVE_REPO=<owner/name> \
//	  go test -tags tinfoil_conformance -run TestLiveVerification ./verifier/conformance/
func TestLiveVerification(t *testing.T) {
	host := os.Getenv("TINFOIL_LIVE_HOST")
	if host == "" {
		t.Skip("set TINFOIL_LIVE_HOST (and TINFOIL_LIVE_REPO) to verify a live enclave")
	}
	repo := os.Getenv("TINFOIL_LIVE_REPO")

	nonce, err := envelope.RandomNonce()
	if err != nil {
		t.Fatalf("nonce: %v", err)
	}
	doc, err := envelope.Fetch(host, nonce)
	if err != nil {
		t.Fatalf("fetch from %s: %v", host, err)
	}

	in := Input{
		SchemaVersion: "1",
		DocumentB64:   base64.StdEncoding.EncodeToString(doc),
		NonceHex:      hex.EncodeToString(nonce),
		Repo:          repo,
	}
	out, code := Run(StageVerify, in) // empty anchors => embedded production roots
	if code != ExitAccepted || out.Outputs == nil {
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
	if _, code := Run(StageVerify, in); code != ExitAccepted {
		t.Fatalf("pinned-time replay of the live document did not accept (exit %d)", code)
	}
}

// tlsSPKIFingerprint dials host:443 and returns the SHA-256 of the presented
// leaf certificate's DER SubjectPublicKeyInfo, lowercase hex. Certificate-chain
// verification is skipped on purpose: trust comes from matching this against
// the attested fingerprint, not from the public PKI.
func tlsSPKIFingerprint(host string) (string, error) {
	conn, err := tls.Dial("tcp", net.JoinHostPort(host, "443"),
		&tls.Config{ServerName: host, InsecureSkipVerify: true}) //nolint:gosec // bound by SPKI, not PKI
	if err != nil {
		return "", err
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "", fmt.Errorf("no peer certificate")
	}
	sum := sha256.Sum256(certs[0].RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:]), nil
}
