package verify

import (
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/tinfoilsh/tinfoil-go/document"
	"github.com/tinfoilsh/tinfoil-go/internal/canonical"
	"github.com/tinfoilsh/tinfoil-go/tinfoil-config/endorsement"
)

// runtimeRepo publishes the measured IGVM images. It is pinned here rather
// than supplied by the caller: a config names the workload, not the runtime it
// happens to be deployed on.
const runtimeRepo = "tinfoilsh/cvmimage"

// ConfigPin is the config a caller will accept. None of it may be learned from
// the document: the whole point of the flow is that the approved config decides
// what the guest is allowed to be running.
//
// Identity and AuditScope are required. Revision and Digest narrow the pin
// further, to one revision of the config or to exact bytes.
type ConfigPin struct {
	Identity   string
	AuditScope string
	Revision   string
	Digest     string
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
	return nil
}

// checkConfigPin reports whether this verifier can appraise pin at all, so a
// caller's mistake surfaces before a document is parsed and never looks like a
// failed attestation.
func (v *Verifier) checkConfigPin(pin ConfigPin) error {
	if v.configVerifier == nil {
		return fmt.Errorf("config verification requires WithConfigSigningKeys")
	}
	if v.ignoreFreshness {
		// A config approval is the only statement that the config has not
		// been withdrawn, and it is timestamped rather than witnessed, so
		// there is nothing left to appraise if freshness is skipped.
		return fmt.Errorf("config verification cannot ignore freshness")
	}
	return pin.Validate()
}

// configReferences is the code-provenance flow against cvmimage, plus the one
// thing a shape-independent launch cannot measure: which config it booted.
// The approved config's digest is the value the launch bound into HOST_DATA or
// MRCONFIGID, and resolving the endorsements against it turns their config
// binding into that expectation.
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
	refs, err := v.codeReferences(doc, runtimeRepo, appraisalTime)
	if err != nil {
		return nil, err
	}
	// approved.Digest is SHA-256 of the same bytes the approval covered, so
	// the expectation and the thing approved cannot be about different
	// configs.
	if refs.Endorsements, err = refs.Endorsements.Resolve(approved.Digest); err != nil {
		return nil, err
	}
	refs.Config = approved
	// The approval carries its own timestamp rather than a witness, and is
	// bounded by the same maximum age as one.
	if deadline := approved.ApprovalTime.Add(v.freshnessMaxAge); refs.FreshnessExpiresAt.IsZero() || deadline.Before(refs.FreshnessExpiresAt) {
		refs.FreshnessExpiresAt = deadline
	}
	return refs, nil
}
