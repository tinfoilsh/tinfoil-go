// Package collaterals defines the wire format of the attestation collaterals
// service: the request an enclave sends at boot and the response carrying
// ready-to-embed v3 collateral entries.
//
// This is service plumbing, not part of the verification API: verifiers never
// see these types. The response embeds envelope.CollateralEntry directly
// so the enclave serves the entries verbatim, with no translation layer.
// Collateral is untrusted transport: the verifier re-checks every signature,
// so a malformed or substituted entry can only cause verification to fail.
package collaterals

import (
	"time"

	"github.com/tinfoilsh/tinfoil-go/verifier/envelope"
)

// FormatV2 identifies the collaterals response carrying v3 collateral entries.
const FormatV2 = "https://tinfoil.sh/predicate/attestation-collaterals/v2"

// Request asks the collaterals service for everything a v3 document must
// carry. The raw quote is the only platform input: the service derives the
// AMD KDS parameters (SEV-SNP) or the Intel PCS URLs (TDX) from it, so the
// enclave does no report parsing.
type Request struct {
	// Repo is the code repository whose Sigstore bundle is returned.
	// Required: the service never guesses a repo.
	Repo string `json:"repo"`
	// Tag optionally pins a code release; latest when empty.
	Tag string `json:"tag,omitempty"`
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

	Collateral []envelope.CollateralEntry `json:"collateral"`
}
