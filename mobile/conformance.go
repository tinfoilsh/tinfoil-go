//go:build tinfoil_conformance

package mobile

import (
	"encoding/base64"
	"encoding/json/v2"
	"fmt"
	"strings"
	"time"

	"github.com/tinfoilsh/tinfoil-go/verify"
)

// This file exists only in a framework built with -tags tinfoil_conformance,
// which tinfoil-swift builds to run the shared conformance vectors through the
// binding. A released framework has none of it: there, as in Go, no trust
// anchor can be replaced and the clock cannot be set.

// conformanceRoots are the trust anchors of a conformance vector, in the
// adapter's wire form (tinfoil-conformance docs/CONFORMANCE_ADAPTER_SPEC.md).
// An absent anchor keeps the embedded one.
type conformanceRoots struct {
	// SigstoreTrustedRootB64 is the Sigstore trusted-root document, base64.
	SigstoreTrustedRootB64 string `json:"sigstore_trusted_root_json_b64,omitempty"`
	// AMDRootCAPEM and ASKPEM are the AMD ARK and its ASK, given together.
	AMDRootCAPEM string `json:"amd_root_ca_pem,omitempty"`
	ASKPEM       string `json:"ask_pem,omitempty"`
	// IntelSGXRootPEM is the Intel SGX root.
	IntelSGXRootPEM string `json:"intel_sgx_root_pem,omitempty"`
}

// NewDangerousTestOnlyVerifier builds a verifier as NewVerifier does with
// default options, but trusting the anchors in rootsJSON, the members of
// conformanceRoots, in place of the embedded ones. Unknown members are
// rejected.
func NewDangerousTestOnlyVerifier(rootsJSON string) (_ *Verifier, err error) {
	defer func() { err = toMobileError(err) }()
	var roots conformanceRoots
	if err := json.Unmarshal([]byte(rootsJSON), &roots, json.RejectUnknownMembers(true)); err != nil {
		return nil, &verify.UsageError{Err: fmt.Errorf("conformance roots: %w", err)}
	}
	var sigstore, amd, intel []byte
	if roots.SigstoreTrustedRootB64 != "" {
		if sigstore, err = base64.StdEncoding.Strict().DecodeString(roots.SigstoreTrustedRootB64); err != nil {
			return nil, &verify.UsageError{Err: fmt.Errorf("sigstore_trusted_root_json_b64: %w", err)}
		}
	}
	switch {
	case roots.AMDRootCAPEM != "" && roots.ASKPEM != "":
		// The chain is ASK then ARK, as AMD's KDS serves it.
		amd = []byte(strings.TrimSpace(roots.ASKPEM) + "\n" + strings.TrimSpace(roots.AMDRootCAPEM) + "\n")
	case roots.AMDRootCAPEM != "" || roots.ASKPEM != "":
		return nil, &verify.UsageError{Err: fmt.Errorf("amd_root_ca_pem and ask_pem must be given together")}
	}
	if roots.IntelSGXRootPEM != "" {
		intel = []byte(roots.IntelSGXRootPEM)
	}
	inner, err := verify.NewVerifier(
		verify.DangerousTestOnlyWithSigstoreRoot(sigstore),
		verify.DangerousTestOnlyWithVendorRoots(amd, intel),
	)
	if err != nil {
		return nil, err
	}
	return &Verifier{inner: inner}, nil
}

// DangerousTestOnlyVerifyAt is Verify with the appraisal clock set to
// unixSeconds, so that a frozen document replays at its capture time.
func (v *Verifier) DangerousTestOnlyVerifyAt(doc, nonce []byte, repo string, unixSeconds int64) (string, error) {
	return v.verifyAt(doc, nonce, repo, time.Unix(unixSeconds, 0))
}
