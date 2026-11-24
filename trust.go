package tinfoil

import (
	"crypto"
	"errors"
	"fmt"
	"slices"

	"github.com/tinfoilsh/tinfoil-go/internal/errs"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/document/collateral"
)

// Trust names who vouches for the config that an enclave runs. It is one of
// RepoPin, ProjectPin, SignedBy, AuthorizedBy, EmbeddedConfig or EitherPin,
// passed as a value; a nil Trust, a pointer to a variant, or another type
// that embeds one is an ErrConfiguration error. Only RepoPin and EitherPin
// accept attestation-collaterals/v2; every other variant requires
// attestation-collaterals/v3.
//
// The pins, RepoPin, ProjectPin and EitherPin, hold only strings, so two
// Trust values that hold pins can be compared with ==, and a pin can be a map
// key. SignedBy, AuthorizedBy and EmbeddedConfig hold keys, a function or
// bytes, which Go can't compare, so == panics when both operands hold the
// same one of those variants. Compare those with a type switch on their
// fields instead: bytes.Equal for EmbeddedConfig's Bytes, and each key's
// Equal method for SignedBy's Keys. AuthorizedBy can't be compared at all,
// since Go can't compare functions, and reflect.DeepEqual reports two
// non-nil functions as unequal even when they are the same one.
type Trust interface {
	trust()
}

// RepoPin trusts v2 collateral for Repo, a GitHub repository
// owner/name[@tag][@sha256:digest]. Repo must not be empty.
type RepoPin struct {
	Repo string
}

// ProjectPin trusts v3 collateral for Project, a config registry project
// org/project[@revision][@sha256:digest], that the trusted registry
// endorses. Project must not be empty.
//
// RegistryID selects the registry that the project lives in. Empty trusts
// Tinfoil's public registry, verify.PublicRegistryID; any other value trusts
// exactly that registry in place of the public one. An application that reads
// a private registry's ID from its configuration should reject a missing
// value itself, since an empty RegistryID selects the public registry rather
// than failing. To accept configs that any of several registries endorse,
// whatever their project, build a verifier with verify.Registries.
type ProjectPin struct {
	Project    string
	RegistryID string
}

// SignedBy trusts v3 configs whose endorsements the caller's Keys sign, in
// place of Tinfoil's registry root. Keys must not be empty. Project, a config
// registry project org/project[@revision][@sha256:digest], optionally
// restricts the configs that are accepted; empty accepts any config that Keys
// sign.
type SignedBy struct {
	Keys    []crypto.PublicKey
	Project string
}

// AuthorizedBy trusts v3 configs that Authorize accepts, in place of a
// registry endorsement. Authorize receives detached, untrusted material and
// must reject unauthorized config bytes; it may be called concurrently.
// Runtime, platform and hardware checks still apply. Approval authenticates
// no registry name or timestamp, so AuthorizedBy has no pin. Authorize must
// not be nil. An error that it returns rejects the enclave with an
// ErrAttestation error that wraps it, without a category that it carries.
type AuthorizedBy struct {
	Authorize func(collateral.ConfigEndorsement) error
}

// EmbeddedConfig trusts v3 collateral for exactly the config Bytes that the
// caller supplies, which must come from trusted client configuration. Name
// optionally associates them with a /org/project/revision identity. It has no
// pin, because a pin would only compare the caller's input against the
// caller's input.
type EmbeddedConfig struct {
	Name  string
	Bytes []byte
}

// EitherPin trusts v2 collateral for Repo or v3 collateral for Project, as
// RepoPin and ProjectPin do. Both must be set. It exists for the migration
// from v2 to v3 collateral and will be removed with v2.
type EitherPin struct {
	Repo    string
	Project string
}

func (RepoPin) trust()        {}
func (ProjectPin) trust()     {}
func (SignedBy) trust()       {}
func (AuthorizedBy) trust()   {}
func (EmbeddedConfig) trust() {}
func (EitherPin) trust()      {}

// verifierInputs converts trust into the verifier's config trust and the pin
// that each verification is made against. It checks only what the variant
// itself requires; verify.NewVerifier and CheckPinVerifiability check the
// values.
func verifierInputs(trust Trust) (verify.ConfigTrust, verify.Pin, error) {
	switch t := trust.(type) {
	case nil:
		return nil, verify.Pin{}, errs.Configuration(errors.New("trust is required"))
	case RepoPin:
		if t.Repo == "" {
			return nil, verify.Pin{}, errs.Configuration(errors.New("RepoPin requires Repo"))
		}
		return nil, verify.Pin{Repo: t.Repo}, nil
	case ProjectPin:
		if t.Project == "" {
			return nil, verify.Pin{}, errs.Configuration(errors.New("ProjectPin requires Project"))
		}
		pin := verify.Pin{Project: t.Project}
		if t.RegistryID == "" {
			return nil, pin, nil
		}
		return verify.Registries{IDs: []string{t.RegistryID}}, pin, nil
	case SignedBy:
		return verify.ConfigSigningKeys{Keys: t.Keys}, verify.Pin{Project: t.Project}, nil
	case AuthorizedBy:
		return verify.ConfigAuthorizer{Authorize: uncategorizedAuthorizer(t.Authorize)}, verify.Pin{}, nil
	case EmbeddedConfig:
		return verify.EmbeddedConfig{Name: t.Name, Bytes: t.Bytes}, verify.Pin{}, nil
	case EitherPin:
		if t.Repo == "" || t.Project == "" {
			return nil, verify.Pin{}, errs.Configuration(errors.New("EitherPin requires both Repo and Project"))
		}
		return nil, verify.Pin{Repo: t.Repo, Project: t.Project}, nil
	default:
		return nil, verify.Pin{}, errs.Configuration(fmt.Errorf("trust must be a RepoPin, ProjectPin, SignedBy, AuthorizedBy, EmbeddedConfig or EitherPin value, not %T", trust))
	}
}

// uncategorizedAuthorizer returns authorize with the categories taken from its
// errors, or nil for nil, which the verifier refuses. The verifier reports a
// refusal as a provenance failure, an attestation error, which a category in
// the authorizer's error would contradict.
func uncategorizedAuthorizer(authorize func(collateral.ConfigEndorsement) error) func(collateral.ConfigEndorsement) error {
	if authorize == nil {
		return nil
	}
	return func(e collateral.ConfigEndorsement) error {
		return errs.Uncategorized(authorize(e))
	}
}

// cloneTrust returns a copy of trust that shares no slice with it. Keys and
// functions are shared, since a caller can't change them through a copy.
func cloneTrust(trust Trust) Trust {
	switch t := trust.(type) {
	case SignedBy:
		t.Keys = slices.Clone(t.Keys)
		return t
	case EmbeddedConfig:
		t.Bytes = slices.Clone(t.Bytes)
		return t
	}
	return trust
}
