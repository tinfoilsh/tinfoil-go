package scope

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/google/uuid"
	configendorsement "github.com/tinfoilsh/tinfoil-go/endorsement/config"
)

type Pins struct {
	OwnerKind      string
	OwnerID        string
	ScopeID        string
	Namespace      string
	SigningKeyHint string
}

func (p Pins) Validate() error {
	if p.OwnerKind != "" && p.OwnerKind != Organization && p.OwnerKind != User {
		return fmt.Errorf("invalid pinned owner kind")
	}
	for _, value := range []string{p.OwnerID, p.ScopeID} {
		if value == "" {
			continue
		}
		id, err := uuid.Parse(value)
		if err != nil || id == uuid.Nil || id.String() != value {
			return fmt.Errorf("pinned owner and scope IDs must be canonical UUIDs")
		}
	}
	if p.Namespace != "" {
		if err := configendorsement.ValidateIdentityComponent(p.Namespace); err != nil {
			return fmt.Errorf("invalid pinned namespace: %w", err)
		}
	}
	if p.SigningKeyHint != "" {
		digest, err := base64.StdEncoding.Strict().DecodeString(p.SigningKeyHint)
		if err != nil || len(digest) != sha256.Size || base64.StdEncoding.EncodeToString(digest) != p.SigningKeyHint {
			return fmt.Errorf("pinned signing key hint must be a base64 SHA-256 fingerprint")
		}
	}
	return nil
}

func (p Pins) Match(identity Identity, keyHint string) error {
	if (p.OwnerKind != "" && p.OwnerKind != identity.OwnerKind) ||
		(p.OwnerID != "" && p.OwnerID != identity.OwnerID) ||
		(p.ScopeID != "" && p.ScopeID != identity.ScopeID) ||
		(p.Namespace != "" && p.Namespace != identity.Namespace) ||
		(p.SigningKeyHint != "" && p.SigningKeyHint != keyHint) {
		return fmt.Errorf("config authority does not match the caller's pins")
	}
	return nil
}
