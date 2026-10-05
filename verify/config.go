package verify

import (
	"cmp"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/tinfoilsh/tinfoil-go/document"
	"github.com/tinfoilsh/tinfoil-go/internal/canonical"
	"github.com/tinfoilsh/tinfoil-go/tinfoil-config/endorsement"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/provenance"
)

// runtimeRepo publishes the measured IGVM images.
const runtimeRepo = "tinfoilsh/cvmimage"

// ConfigPin is the config a caller will accept; none of it may be learned from
// the document. Identity and AuditScope are required, and Revision and Digest
// narrow the pin to one revision or to exact bytes.
type ConfigPin struct {
	Identity   string
	AuditScope string
	Revision   string
	Digest     string
	// Runtime optionally pins which cvmimage release this caller accepts, in
	// VerifyV3's owner/name[@tag][@sha256:digest] grammar. It binds only for
	// callers that set it; empty accepts whichever release the document
	// names, bounded by that release's freshness witness.
	Runtime string
}

// Validate reports whether the pin is usable.
func (p ConfigPin) Validate() error {
	if err := endorsement.ValidateIdentity(p.Identity); err != nil {
		return err
	}
	if err := endorsement.ValidateAuditScope(p.AuditScope); err != nil {
		return err
	}
	if p.Revision != "" {
		if _, _, err := endorsement.ParseName(p.Identity + "/" + p.Revision); err != nil {
			return err
		}
	}
	if p.Digest != "" {
		if _, err := canonical.DecodeLowerHex("config digest pin", p.Digest, sha256.Size); err != nil {
			return err
		}
	}
	if p.Runtime != "" {
		repo, _, _, err := provenance.ParseReference(p.Runtime)
		if err != nil {
			return err
		}
		if repo != runtimeRepo {
			return fmt.Errorf("runtime pin names repository %q, want %q", repo, runtimeRepo)
		}
	}
	return nil
}

// checkConfigPin reports whether this verifier can appraise pin at all, so a
// caller's mistake never looks like a failed attestation.
func (v *Verifier) checkConfigPin(pin ConfigPin) error {
	if v.configVerifier == nil {
		return fmt.Errorf("config verification requires WithConfigSigningKeys")
	}
	if v.ignoreFreshness {
		// The approval's timestamp is the only statement that the config has
		// not been withdrawn, so skipping it leaves nothing to appraise.
		return fmt.Errorf("config verification cannot ignore freshness")
	}
	return pin.Validate()
}

// configReferences is the code-provenance flow against cvmimage, plus the one
// thing the launch cannot measure: the approved config's digest, which is the
// value it bound into HOST_DATA or MRCONFIGID.
func (v *Verifier) configReferences(doc *document.Document, pin ConfigPin, appraisalTime time.Time) (*references, error) {
	entry, err := doc.ConfigEndorsement()
	if err != nil {
		return nil, err
	}
	approved, err := v.configVerifier.Verify(entry.Config, entry.Bundle, endorsement.Policy{
		Identity: pin.Identity, AuditScope: pin.AuditScope, Revision: pin.Revision,
		Digest: pin.Digest, Now: appraisalTime, MaxAge: v.freshnessMaxAge,
	})
	if err != nil {
		return nil, fmt.Errorf("verifying config approval: %w", err)
	}
	// AuthenticateCode gives a pin in the reference precedence over the
	// document's tag and digest hints.
	refs, err := v.codeReferences(doc, cmp.Or(pin.Runtime, runtimeRepo), appraisalTime)
	if err != nil {
		return nil, err
	}
	// approved.Digest is SHA-256 of the bytes the approval covered.
	if refs.Endorsements, err = refs.Endorsements.Resolve(approved.Digest); err != nil {
		return nil, err
	}
	refs.Config = approved
	// The approval is timestamped rather than witnessed, under the same
	// maximum age.
	if deadline := approved.ApprovalTime.Add(v.freshnessMaxAge); refs.FreshnessExpiresAt.IsZero() || deadline.Before(refs.FreshnessExpiresAt) {
		refs.FreshnessExpiresAt = deadline
	}
	return refs, nil
}
