//go:build tinfoil_conformance

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	tinfoilattestation "github.com/tinfoilsh/tinfoil-go/verifier/attestation"
)

func cmdVerifyAttestationTDXPublic(in verifyAttestationTdxInput, quoteBytes []byte, getter *injectedGetter) int {
	doc, err := tinfoilattestation.NewDocument(tinfoilattestation.TdxGuestV2, quoteBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "internal: failed to create TDX document: %v\n", err)
		return exitInternal
	}

	tcbEval := tcbEvaluationRequired(in.Policy)
	opts := &tinfoilattestation.TDXVerificationOptions{
		Getter:           getter,
		Now:              time.Unix(in.ExpirationCheckDateUnix, 0).UTC(),
		GetCollateral:    boolPtr(tcbEval),
		CheckRevocations: boolPtr(tcbEval),
	}
	if in.Collateral.IntelRootCAPEM != "" {
		pool, err := trustedRootsFromPEM(in.Collateral.IntelRootCAPEM)
		if err != nil {
			return emitTdxRejection("ROOT_CA_UNTRUSTED", "4.2", err.Error())
		}
		opts.TrustedRoots = pool
	}

	var verifyErr error
	withStdoutSilenced(func() {
		_, verifyErr = doc.VerifyWithTDXOptions(opts)
	})
	if verifyErr != nil {
		code, ref := classifyTdxError(verifyErr)
		return emitTdxRejection(code, ref, verifyErr.Error())
	}

	if code, msg := enforceTcbEvaluationDataNumberPolicy(in); code != "" {
		return emitTdxRejection(code, "4.7.11", msg)
	}
	if in.Policy != nil {
		if code, msg := enforceExtendedPolicy(quoteBytes, in.Policy); code != "" {
			return emitTdxRejection(code, "4.8", msg)
		}
	}

	body, err := buildTdxOutputs(nil, quoteBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "internal: failed to assemble outputs: %v\n", err)
		return exitInternal
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(body); err != nil {
		fmt.Fprintf(os.Stderr, "internal error: %v\n", err)
		return exitInternal
	}
	return exitAccept
}
