//go:build tinfoil_conformance

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/tinfoilsh/tinfoil-go/internal/fetch"
	"github.com/tinfoilsh/tinfoil-go/internal/transport"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/conformance"
	"github.com/tinfoilsh/tinfoil-go/verify/document"
)

const stageLive = "live-verify"

// liveRequest is the integration-lane stdin JSON (spec §7).
type liveRequest struct {
	Host string `json:"host"`
	Repo string `json:"repo"`
	// Project is absent in requests that predate separate pins, where repo
	// names the workload in either namespace.
	Project *string `json:"project,omitempty"`
}

// runLive verifies a live enclave through the SDK's production verifier —
// verify.NewVerifier with no options, so the embedded roots, the current time
// and the default freshness bound, never the adapter's injected seams — then
// asserts the live connection's SPKI fingerprint equals the endorsed one
// before reporting the facts with channel_binding "tls-spki".
func runLive() int {
	var req liveRequest
	dec := json.NewDecoder(os.Stdin)
	if err := dec.Decode(&req); err != nil || dec.Decode(new(any)) != io.EOF || req.Host == "" || req.Repo == "" {
		writeJSON(conformance.Output{Stage: stageLive, Rejection: &conformance.Rejection{Code: "MALFORMED_INPUT"}})
		return conformance.ExitMalformed
	}

	v, err := verify.NewVerifier()
	if err != nil {
		fmt.Fprintf(os.Stderr, "building verifier: %v\n", err)
		return conformance.ExitInternal
	}

	nonce, err := document.RandomNonce()
	if err != nil {
		fmt.Fprintf(os.Stderr, "nonce: %v\n", err)
		return conformance.ExitInternal
	}
	doc, err := fetch.Document(context.Background(), req.Host, "", nonce)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fetching attestation from %s: %v\n", req.Host, err)
		return conformance.ExitInternal
	}

	pin := verify.Pin{Repo: req.Repo, Project: req.Repo}
	if req.Project != nil {
		pin.Project = *req.Project
	}
	verified, err := v.VerifyV3(doc, nonce, pin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "live verification: %v\n", err)
		code, exit := conformance.RejectionCode(err)
		if exit != conformance.ExitInternal {
			writeJSON(conformance.Output{Stage: stageLive, Rejection: &conformance.Rejection{Code: code}})
		}
		return exit
	}
	tlsFP, ok := verified.TLSPublicKeyFP()
	if !ok {
		fmt.Fprintf(os.Stderr, "endorsed keys: document endorses no %q key in format %q\n", document.CryptoMaterialIDTLS, document.KeySPKIFPSHA256V1Format)
		return rejectLive("ENVELOPE_REJECTED")
	}
	hpke, ok := verified.HPKEPublicKey()
	if !ok {
		fmt.Fprintf(os.Stderr, "endorsed keys: document endorses no %q key in format %q\n", document.CryptoMaterialIDHPKE, document.KeyX25519HPKEV1Format)
		return rejectLive("ENVELOPE_REJECTED")
	}

	// Channel binding: the endorsed TLS key must be the key the live enclave
	// actually presents on the wire.
	live, err := tlsSPKIFingerprint(req.Host)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dialing %s for channel binding: %v\n", req.Host, err)
		return conformance.ExitInternal
	}
	if live != tlsFP {
		fmt.Fprintf(os.Stderr, "channel binding: live TLS key %s != endorsed %s\n", live, tlsFP)
		return rejectLive("POLICY_REJECTED")
	}

	writeJSON(conformance.Output{Stage: stageLive, Accepted: true, Outputs: &conformance.AcceptOutputs{
		CodeDigest:         verified.CodeDigest(),
		CodeMeasurement:    conformance.ExpectedOf(verified.CodeMeasurement()),
		EnclaveMeasurement: conformance.MeasurementOf(verified.EnclaveMeasurement()),
		TLSPublicKeyFP:     tlsFP,
		HPKEPublicKey:      hpke,
		ChannelBinding:     "tls-spki",
	}})
	return conformance.ExitAccepted
}

// tlsSPKIFingerprint dials host (port 443 unless host names one) and returns
// the SPKI fingerprint of the leaf certificate that it presents, computed by
// transport.ConnectionCertFP: the function that the client's pinned transport
// uses. Certificate-chain verification is skipped on purpose: trust comes
// from matching the attested fingerprint, not from the public PKI.
func tlsSPKIFingerprint(host string) (string, error) {
	addr, serverName := host, host
	if h, _, err := net.SplitHostPort(host); err == nil {
		serverName = h // host already carries a port
	} else {
		addr = net.JoinHostPort(host, "443")
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr,
		&tls.Config{ServerName: serverName, InsecureSkipVerify: true}) //nolint:gosec // bound by SPKI, not PKI
	if err != nil {
		return "", err
	}
	defer conn.Close()
	return transport.ConnectionCertFP(conn.ConnectionState())
}

func rejectLive(code string) int {
	writeJSON(conformance.Output{Stage: stageLive, Accepted: false, Rejection: &conformance.Rejection{Code: code}})
	return conformance.ExitRejected
}
