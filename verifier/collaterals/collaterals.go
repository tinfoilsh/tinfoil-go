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

	"github.com/tinfoilsh/tinfoil-go/verifier/document/collateral"
)

// FormatV2 identifies the collaterals response carrying v3 collateral entries.
const FormatV2 = "https://tinfoil.sh/predicate/attestation-collaterals/v2"

const (
	ProfileIGVMV1 = "https://tinfoil.sh/predicate/attestation-collaterals/igvm/v1"
	RuntimeRepo   = collateral.RuntimeRepo
)

// Request asks the collaterals service for everything a v3 document must
// carry. The raw quote is the only platform input: the service derives the
// AMD KDS parameters (SEV-SNP) or the Intel PCS URLs (TDX) from it, so the
// enclave does no report parsing.
type Request struct {
	Profile string                       `json:"profile,omitempty"`
	Runtime *collateral.RuntimeReference `json:"runtime,omitempty"`
	// Repo is the code repository whose Sigstore bundle is returned.
	// The IGVM profile requires Runtime and Config instead of Repo and Tag.
	Repo string `json:"repo,omitempty"`
	// Tag optionally pins a code release; latest when empty.
	Tag string `json:"tag,omitempty"`
	// Config pins a versioned registry config and its exact-byte digest.
	Config *collateral.ConfigReference `json:"config,omitempty"`
	// Platform is attestation's platform label: "sev-snp" or "tdx".
	Platform string `json:"platform"`
	// QuoteBase64 is the raw hardware report (SEV-SNP, 1184 bytes) or quote
	// (TDX v4, with certification data) in standard base64.
	QuoteBase64 string `json:"quote_base64"`
}

// Response carries the complete collateral array for a v3 attestation
// document: the platform endorsement entry (amd-vcek or intel-pcs) and the
// two reference-values entries (sigstore-code, sigstore-platform).
type Response struct {
	Format    string    `json:"format"`
	ExpiresAt time.Time `json:"expires_at"`

	Collateral []collateral.Entry `json:"collateral"`
}
