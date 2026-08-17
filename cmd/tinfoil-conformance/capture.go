//go:build tinfoil_conformance

package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/tinfoilsh/tinfoil-go/verifier/conformance"
	"github.com/tinfoilsh/tinfoil-go/verifier/envelope"
)

// runCapture fetches a v3 attestation from a live enclave and, only if it
// verifies against the embedded production roots, freezes it as a real-frozen
// fixture pinned to its capture time — the accepting embedded-root oracle that
// synthetic fixtures cannot produce.
func runCapture(args []string) int {
	fs := flag.NewFlagSet("capture", flag.ContinueOnError)
	host := fs.String("host", "", "enclave host to fetch the v3 attestation from (e.g. inference.tinfoil.sh)")
	repo := fs.String("repo", "", "pinned sigstore-code source repo (owner/name)")
	id := fs.String("id", "real-frozen", "fixture id")
	out := fs.String("out", "", "output fixture path (default: stdout)")
	nonceHex := fs.String("nonce", "", "verifier nonce, lowercase hex (default: fresh random)")
	if err := fs.Parse(args); err != nil {
		return conformance.ExitMalformed
	}
	if *host == "" || *repo == "" {
		fmt.Fprintln(os.Stderr, "usage: tinfoil-conformance capture -host <enclave> -repo <owner/name> [-id ..] [-out ..] [-nonce ..]")
		return conformance.ExitMalformed
	}

	nonce, err := resolveNonce(*nonceHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "nonce: %v\n", err)
		return conformance.ExitMalformed
	}

	doc, err := envelope.Fetch(*host, nonce)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fetching attestation from %s: %v\n", *host, err)
		return conformance.ExitInternal
	}

	// Pin to the capture instant: collateral is fresh now, and this is what
	// every future replay reproduces.
	captureUnix := time.Now().Unix()
	in := conformance.Input{
		SchemaVersion:        conformance.SchemaVersion,
		DocumentB64:          base64.StdEncoding.EncodeToString(doc),
		NonceHex:             hex.EncodeToString(nonce),
		Repo:                 *repo,
		VerificationTimeUnix: captureUnix,
	}

	// Verify through the real embedded-root path (empty anchors) at the pinned
	// time before freezing; refuse to write a document the verifier rejects.
	if outp, code := conformance.Run(conformance.StageVerify, in); code != conformance.ExitAccepted {
		msg := "unknown"
		if outp.Rejection != nil {
			msg = outp.Rejection.Code
		}
		fmt.Fprintf(os.Stderr, "refusing to freeze: verification did not accept (exit %d, %s)\n", code, msg)
		return code
	}

	fixture := map[string]any{
		"id":       *id,
		"stage":    conformance.StageVerify,
		"input":    in,
		"expected": map[string]any{"accepted": true},
	}
	b, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "encoding fixture: %v\n", err)
		return conformance.ExitInternal
	}
	b = append(b, '\n')

	if *out == "" {
		os.Stdout.Write(b)
	} else if err := os.WriteFile(*out, b, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "writing %s: %v\n", *out, err)
		return conformance.ExitInternal
	} else {
		fmt.Fprintf(os.Stderr, "froze real v3 document -> %s (verified at capture time %d)\n", *out, captureUnix)
	}
	return conformance.ExitAccepted
}

// resolveNonce returns the supplied hex nonce or a fresh random one.
func resolveNonce(h string) ([]byte, error) {
	if h == "" {
		return envelope.RandomNonce()
	}
	n, err := hex.DecodeString(h)
	if err != nil {
		return nil, err
	}
	if len(n) != envelope.NonceSize {
		return nil, fmt.Errorf("nonce must be %d bytes, got %d", envelope.NonceSize, len(n))
	}
	return n, nil
}
