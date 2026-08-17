//go:build tinfoil_conformance

// Command tinfoil-conformance is the tinfoil-go conformance adapter the
// cross-SDK suite invokes: `tinfoil-conformance <stage>` reads an Input JSON on
// stdin and writes an Output JSON on stdout, exiting with the adapter code.
// `tinfoil-conformance capabilities` prints the SDK's capabilities.
// `tinfoil-conformance capture` fetches a live enclave's v3 attestation and
// freezes it as a real-frozen fixture (see capture.go).
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/tinfoilsh/tinfoil-go/verifier/conformance"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: tinfoil-conformance <stage>|capabilities|capture")
		os.Exit(conformance.ExitMalformed)
	}
	cmd := os.Args[1]

	if cmd == "capabilities" {
		writeJSON(conformance.Capabilities())
		return
	}

	if cmd == "capture" {
		os.Exit(runCapture(os.Args[2:]))
	}

	var in conformance.Input
	dec := json.NewDecoder(os.Stdin)
	if err := dec.Decode(&in); err != nil || dec.Decode(new(any)) != io.EOF {
		// Exactly one JSON value: trailing data is malformed input.
		writeJSON(conformance.Output{Stage: cmd, Rejection: &conformance.Rejection{Code: "MALFORMED_INPUT"}})
		os.Exit(conformance.ExitMalformed)
	}

	out, code := conformance.Run(cmd, in)
	writeJSON(out)
	os.Exit(code)
}

func writeJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fmt.Fprintf(os.Stderr, "writing output: %v\n", err)
		os.Exit(conformance.ExitInternal)
	}
}
