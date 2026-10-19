package verify

import (
	"fmt"
	"time"

	"github.com/tinfoilsh/tinfoil-go/verify/document"
	"github.com/tinfoilsh/tinfoil-go/verify/document/collateral"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/errs"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/quote"
)

// CollateralCheck supplies a raw CPU quote and candidate collateral to an
// availability check. Reference has the same meaning as VerifyV3's repo.
// Runtime selects a local-config check instead: it excludes Reference and
// config collateral because the private config is not supplied.
type CollateralCheck struct {
	Evidence  document.CPUEvidence
	Format    string
	Entries   []collateral.Entry
	Reference string
	Runtime   *collateral.RuntimeReference
}

// CollateralCompatibility describes compatibility at the time of appraisal.
// It is not an attestation result and cannot authorize a connection. The check
// has no client nonce, application keys, device evidence, or private config.
type CollateralCompatibility struct {
	// WorkloadChecked is false for a local-config runtime-only check.
	WorkloadChecked    bool
	FreshnessExpiresAt time.Time
}

// CheckCollateral authenticates candidate collateral and checks its CPU policy
// against a raw quote. It does not check REPORT_DATA bindings or prove liveness.
// A local-config check validates the runtime and platform, but not the private
// config hash or its authorization. Clients must still run VerifyV3 themselves.
func (v *Verifier) CheckCollateral(in CollateralCheck) (*CollateralCompatibility, error) {
	if v == nil || v.now == nil || v.endorsements == nil || v.configVerifier == nil || v.freshnessVerifier == nil {
		return nil, usageError(fmt.Errorf("verifier must be built with NewVerifier"))
	}
	set, err := document.DecodeCollateral(in.Format, in.Entries)
	if err != nil {
		return nil, errs.WrapVerification(err)
	}
	material := collateralMaterial{set}
	now := v.now()
	var refs *endorsementResult
	if in.Runtime != nil {
		if in.Format != collateral.FormatV3 || in.Reference != "" || set.Config != nil || v.embedded.Config != nil || v.configAuthorizer != nil || v.configKeys != nil {
			return nil, usageError(fmt.Errorf("runtime-only collateral check requires v3 without config or workload trust"))
		}
		if err := in.Runtime.Validate(); err != nil {
			return nil, usageError(err)
		}
		manifest, runtimeTrust, err := v.resolveRuntime(material, *in.Runtime, now)
		if err != nil {
			return nil, errs.WrapVerification(err)
		}
		platform, platformTrust, err := v.resolvePlatform(material, now)
		if err != nil {
			return nil, errs.WrapVerification(err)
		}
		authenticated, err := quote.Authenticate(in.Evidence, set.CPU, v.quoteOptions(now))
		if err != nil {
			return nil, err
		}
		if err := quote.CheckRuntimeCompatibility(platform, manifest.Measurements, v.pinnedRegisters, authenticated); err != nil {
			return nil, err
		}
		result := &CollateralCompatibility{}
		if !v.ignoreFreshness {
			result.FreshnessExpiresAt = freshnessExpiration(v.freshnessMaxAge, platformTrust.ApprovalTime, runtimeTrust.ApprovalTime)
		}
		return result, nil
	}
	switch in.Format {
	case "", collateral.FormatV2:
		refs, err = v.codeReferences(material, in.Reference, now)
	case collateral.FormatV3:
		refs, err = v.configReferences(material, in.Reference, now)
	}
	if err != nil {
		return nil, errs.WrapVerification(err)
	}
	authenticated, err := quote.Authenticate(in.Evidence, set.CPU, v.quoteOptions(now))
	if err != nil {
		return nil, err
	}
	if err := quote.CheckCompatibility(refs.quote, v.pinnedRegisters, authenticated); err != nil {
		return nil, err
	}
	return &CollateralCompatibility{WorkloadChecked: true, FreshnessExpiresAt: refs.freshnessExpiresAt}, nil
}

// referenceMaterial separates endorsement appraisal from the document's
// nonce and key bindings, which only VerifyV3 can establish.
type referenceMaterial interface {
	SigstoreCode() (collateral.SigstoreRef, error)
	SigstorePlatform() (collateral.SigstoreRef, error)
	Freshness(string) (collateral.Freshness, error)
	ConfigEndorsement() (collateral.ConfigEndorsement, error)
	Runtime() (collateral.Runtime, error)
	ConfigPlatform() (collateral.SigstoreRef, error)
}

type collateralMaterial struct {
	set collateral.Set
}

func (m collateralMaterial) SigstoreCode() (collateral.SigstoreRef, error) {
	if m.set.SigstoreCode == nil {
		return collateral.SigstoreRef{}, fmt.Errorf("%w: no %s reference values", collateral.ErrNotFound, collateral.SigstoreCodeV1Format)
	}
	return m.set.SigstoreCode.Clone(), nil
}

func (m collateralMaterial) SigstorePlatform() (collateral.SigstoreRef, error) {
	if m.set.SigstorePlatform == nil {
		return collateral.SigstoreRef{}, fmt.Errorf("%w: no %s reference values", collateral.ErrNotFound, collateral.SigstorePlatformV1Format)
	}
	return m.set.SigstorePlatform.Clone(), nil
}

func (m collateralMaterial) Freshness(id string) (collateral.Freshness, error) {
	value, ok := m.set.Freshness[id]
	if !ok {
		return collateral.Freshness{}, fmt.Errorf("%w: no freshness entry %q", collateral.ErrNotFound, id)
	}
	return value.Clone(), nil
}

func (m collateralMaterial) ConfigEndorsement() (collateral.ConfigEndorsement, error) {
	if m.set.Config == nil {
		return collateral.ConfigEndorsement{}, fmt.Errorf("%w: no %q reference values", collateral.ErrNotFound, collateral.ConfigID)
	}
	return m.set.Config.Clone(), nil
}

func (m collateralMaterial) Runtime() (collateral.Runtime, error) {
	if m.set.Runtime == nil {
		return collateral.Runtime{}, fmt.Errorf("%w: no %q reference values", collateral.ErrNotFound, collateral.RuntimeID)
	}
	return m.set.Runtime.Clone(), nil
}

func (m collateralMaterial) ConfigPlatform() (collateral.SigstoreRef, error) {
	return m.set.ConfigPlatform()
}
