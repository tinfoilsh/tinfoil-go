// Package collaterals defines the wire format of the attestation collaterals
// service: the request an enclave sends at boot and the response carrying
// ready-to-embed v3 collateral entries.
//
// This is service plumbing, not part of the verification API: verifiers never
// see these types. The response embeds document.CollateralEntry directly
// so the enclave serves the entries verbatim, with no translation layer.
// Collateral is untrusted transport: the verifier re-checks every signature,
// so a malformed or substituted entry can only cause verification to fail.
package collaterals

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/tinfoilsh/tinfoil-go/verifier/document"
)

// FormatV2 identifies the collaterals response carrying v3 collateral entries.
const FormatV2 = "https://tinfoil.sh/predicate/attestation-collaterals/v2"

const (
	platformDummy           = "dummy"
	maxConfigSlugLength     = 63
	maxConfigRevisionLength = 128
)

var (
	configNamePattern   = regexp.MustCompile(`^/[a-z0-9]+(?:-[a-z0-9]+)*/[a-z0-9]+(?:-[a-z0-9]+)*/[A-Za-z0-9][A-Za-z0-9._-]*$`)
	configDigestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

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
	// Config pins a versioned registry config and its exact-byte digest.
	Config *document.ConfigReference `json:"config,omitempty"`
	// Platform is attestation's platform label: "sev-snp" or "tdx".
	Platform string `json:"platform"`
	// QuoteBase64 is the raw hardware report (SEV-SNP, 1184 bytes) or quote
	// (TDX v4, with certification data) in standard base64.
	QuoteBase64 string `json:"quote_base64"`
}

// Validate checks transport selection; it does not authenticate the requested config.
func (r Request) Validate() error {
	if r.Platform == "" || r.QuoteBase64 == "" {
		return fmt.Errorf("collateral request requires platform and quote_base64")
	}
	if r.Config == nil {
		if r.Repo == "" && r.Platform != platformDummy {
			return fmt.Errorf("collateral request requires a repository or config reference")
		}
		return nil
	}
	if r.Repo != "" || r.Tag != "" {
		return fmt.Errorf("config and repository sources are mutually exclusive")
	}
	if !configNamePattern.MatchString(r.Config.Name) || !configDigestPattern.MatchString(r.Config.Digest) {
		return fmt.Errorf("config reference requires a canonical name and lowercase SHA-256 digest")
	}
	parts := strings.Split(r.Config.Name, "/")
	for _, part := range parts[1 : len(parts)-1] {
		if len(part) > maxConfigSlugLength {
			return fmt.Errorf("config identity component is too long")
		}
	}
	if len(parts[len(parts)-1]) > maxConfigRevisionLength {
		return fmt.Errorf("config revision is too long")
	}
	return nil
}

// Response carries the complete collateral array for a v3 attestation
// document: the platform endorsement entry (amd-vcek or intel-pcs) and the
// two reference-values entries (sigstore-code, sigstore-platform).
type Response struct {
	Format    string    `json:"format"`
	ExpiresAt time.Time `json:"expires_at"`

	Collateral []document.CollateralEntry `json:"collateral"`
}
