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

// FormatV2 identifies the legacy GitHub workload-release collateral response.
const FormatV2 = collateral.FormatV2

const (
	// FormatV3 identifies the request profile and response carrying config
	// endorsement, runtime/platform provenance, and Tinfoil-signed freshness.
	FormatV3    = collateral.FormatV3
	RuntimeRepo = collateral.RuntimeRepo
)

// Request asks the collaterals service for everything a v3 document must
// carry. The raw quote is the only platform input: the service derives the
// AMD KDS parameters (SEV-SNP) or the Intel PCS URLs (TDX) from it, so the
// enclave does no report parsing.
type Request struct {
	// Profile is FormatV3 for registry or local configs, or empty for legacy releases.
	Profile string `json:"profile,omitempty"`
	// Repo is a GitHub repository or, for FormatV3, a registry org/project.
	Repo string `json:"repo,omitempty"`
	// Tag is the registry config revision for FormatV3; otherwise an optional release tag.
	Tag string `json:"tag,omitempty"`
	// Digest pins the exact config bytes for FormatV3 and is empty for legacy releases.
	Digest string `json:"digest,omitempty"`
	// Runtime pins a cvm version and manifest digest for a local config.
	// It requires FormatV3 and excludes Repo, Tag, and Digest.
	Runtime string `json:"runtime,omitempty"`
	// Platform is attestation's platform label: "sev-snp" or "tdx".
	Platform string `json:"platform"`
	// QuoteBase64 is the raw hardware report (SEV-SNP, 1184 bytes) or quote
	// (TDX v4, with certification data) in standard base64.
	QuoteBase64 string `json:"quote_base64"`
}

// Response carries the collateral array for a v3 attestation document.
// Format must match the requested profile: FormatV2 for an empty profile,
// or FormatV3 for a FormatV3 request.
type Response struct {
	Format    string    `json:"format"`
	ExpiresAt time.Time `json:"expires_at"`

	Collateral []collateral.Entry `json:"collateral"`
}
