// Package collaterals defines the wire format of the attestation collaterals
// service: the request an enclave sends at boot and the response carrying
// ready-to-embed v3 collateral entries.
//
// This is service plumbing, not part of the verification API: verifiers never
// see these types. The response embeds collateral.Entry directly
// so the enclave serves the entries verbatim, with no translation layer.
// Collateral is untrusted transport: the verifier re-checks every signature,
// so a malformed or substituted entry can only cause verification to fail.
package collaterals

import (
	"time"

	"github.com/tinfoilsh/tinfoil-go/document/collateral"
)

// FormatV2 identifies the collaterals response carrying v3 collateral entries.
const FormatV2 = "https://tinfoil.sh/predicate/attestation-collaterals/v2"

// Request asks the collaterals service for everything a v3 document must
// carry. The raw quote is the only platform input: the service derives the
// AMD KDS parameters (SEV-SNP) or the Intel PCS URLs (TDX) from it, so the
// enclave does no report parsing.
type Request struct {
	// Repo is the code repository whose Sigstore bundle is returned.
	// Exactly one of Repo or Config selects the config source.
	Repo string `json:"repo,omitempty"`
	// Tag optionally pins a code release; latest when empty.
	Tag string `json:"tag,omitempty"`
	// Config pins a versioned registry config and its exact-byte digest. A
	// guest that bound its config into HOST_DATA or MRCONFIGID already knows
	// the digest, because it is the value it wrote there; the name comes from
	// however the config was delivered to it. Sending Config rather than Repo
	// selects the config flow and is the whole of the guest's side of it.
	Config *collateral.ConfigReference `json:"config,omitempty"`
	// Platform is attestation's platform label: "sev-snp" or "tdx".
	Platform string `json:"platform"`
	// QuoteBase64 is the raw hardware report (SEV-SNP, 1184 bytes) or quote
	// (TDX v4, with certification data) in standard base64.
	QuoteBase64 string `json:"quote_base64"`
}

// Response carries the complete collateral array for a v3 attestation
// document.
//
// A Repo request is answered with the CPU endorsement entries (amd-vcek and
// amd-crl, or intel-pcs) and the reference-values entries "code", "platform",
// "code-freshness" and "platform-freshness".
//
// A Config request is answered with exactly the same entries plus one:
//
//	tinfoil-config  config-endorsement/v1  {config_base64, sigstore_bundle}
//
// The two differences are in what the existing entries carry, not in which
// entries exist. "code" is the cvmimage runtime release rather than a workload
// release, so its measurement predicate is the IGVM one; and "platform" is
// platform-endorsements-igvm.json, whose policies declare a config binding
// instead of a fixed host_data. Both freshness witnesses are unchanged, and
// the cvmimage release is witnessed through "code-freshness" like any other.
type Response struct {
	Format    string    `json:"format"`
	ExpiresAt time.Time `json:"expires_at"`

	Collateral []collateral.Entry `json:"collateral"`
}
