//go:build tinfoil_conformance

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/conformance"
	"github.com/tinfoilsh/tinfoil-go/verify/document"
)

const stageLive = "live-verify"

// liveRequest is the integration-lane stdin JSON (spec §7).
type liveRequest struct {
	Host string `json:"host"`
	Repo string `json:"repo"`
}

// runLive verifies a live enclave through the SDK's production verifier —
// verify.New with no options, so the embedded roots, the current time and
// the default freshness bound, never the adapter's injected seams — then
// asserts the live connection's SPKI fingerprint equals the endorsed one
// before reporting the facts with channel_binding "tls-spki". It calls
// VerifyV3WithLayer, which runs exactly VerifyV3 and also names the layer
// that rejected a document.
func runLive() int {
	var req liveRequest
	dec := json.NewDecoder(os.Stdin)
	if err := dec.Decode(&req); err != nil || dec.Decode(new(any)) != io.EOF || req.Host == "" || req.Repo == "" {
		writeJSON(conformance.Output{Stage: stageLive, Rejection: &conformance.Rejection{Code: "MALFORMED_INPUT"}})
		return conformance.ExitMalformed
	}

	v, err := verify.New()
	if err != nil {
		fmt.Fprintf(os.Stderr, "building verifier: %v\n", err)
		return conformance.ExitInternal
	}

	nonce, err := document.RandomNonce()
	if err != nil {
		fmt.Fprintf(os.Stderr, "nonce: %v\n", err)
		return conformance.ExitInternal
	}
	doc, err := document.Fetch(req.Host, nonce)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fetching attestation from %s: %v\n", req.Host, err)
		return conformance.ExitInternal
	}

	verified, layer, err := v.VerifyV3WithLayer(doc, nonce, req.Repo)
	if err != nil {
		fmt.Fprintf(os.Stderr, "live verification: %v\n", err)
		return rejectLive(conformance.RejectionCode(layer))
	}
	tlsFP, err := verified.TLSPublicKeyFP()
	if err != nil {
		fmt.Fprintf(os.Stderr, "endorsed keys: %v\n", err)
		return rejectLive("ENVELOPE_REJECTED")
	}
	hpke, err := verified.HPKEPublicKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "endorsed keys: %v\n", err)
		return rejectLive("ENVELOPE_REJECTED")
	}

	// Channel binding: the endorsed TLS key must be the key the live enclave
	// actually presents on the wire.
	live, err := conformance.TLSSPKIFingerprint(req.Host)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dialing %s for channel binding: %v\n", req.Host, err)
		return conformance.ExitInternal
	}
	if live != tlsFP {
		fmt.Fprintf(os.Stderr, "channel binding: live TLS key %s != endorsed %s\n", live, tlsFP)
		return rejectLive("POLICY_REJECTED")
	}

	writeJSON(conformance.Output{Stage: stageLive, Accepted: true, Outputs: &conformance.AcceptOutputs{
		CodeDigest: verified.CodeDigest,
		CodeMeasurement: conformance.Measurement{
			Type:      string(verified.CodeMeasurement.Type),
			Registers: verified.CodeMeasurement.Registers,
		},
		EnclaveMeasurement: conformance.Measurement{
			Type:      string(verified.EnclaveMeasurement.Type),
			Registers: verified.EnclaveMeasurement.Registers,
		},
		TLSPublicKeyFP: tlsFP,
		HPKEPublicKey:  hpke,
		ChannelBinding: "tls-spki",
	}})
	return conformance.ExitAccepted
}

func rejectLive(code string) int {
	writeJSON(conformance.Output{Stage: stageLive, Accepted: false, Rejection: &conformance.Rejection{Code: code}})
	return conformance.ExitRejected
}
