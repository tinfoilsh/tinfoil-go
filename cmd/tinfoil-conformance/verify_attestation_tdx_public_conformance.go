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

	// Re-baseline the verifier to the synthetic vector's own TD-body baseline.
	// Production verification (tdx.go) hard-codes the real Tinfoil enclave's
	// expected TD_ATTRIBUTES/XFAM/MinimumTeeTcbSvn/MrSeam, which synthetic test
	// vectors don't match — that would reject them before the fixture's
	// targeted check. The fixture's §4.8 pins are still enforced precisely by
	// enforceExtendedPolicy below. Mirrors tinfoil-python's TdxVerificationConfig.
	// Body field offsets match enforceExtendedPolicy (header[:48], body[48:632]).
	if len(quoteBytes) >= 48+584 {
		body := quoteBytes[48 : 48+584]
		opts.ExpectedMinimumTeeTcbSvn = append([]byte(nil), body[0:16]...)
		opts.AcceptedMrSeams = [][]byte{append([]byte(nil), body[16:64]...)}
		opts.ExpectedTdAttributes = append([]byte(nil), body[120:128]...)
		opts.ExpectedXfam = append([]byte(nil), body[128:136]...)
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
