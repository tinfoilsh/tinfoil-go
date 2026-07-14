// Package policy defines the appraisal-policy language: the schema of the
// Sigstore-signed platform-endorsements artifact (predicate
// https://tinfoil.sh/predicate/platform-endorsements/v1) and the
// authenticated lookups over it. The artifact's wire name predates the
// RATS vocabulary: its contents are reference values and appraisal
// policies, not RATS endorsements (those are the hardware-vendor
// collateral entries).
//
// The artifact maps hardware identifiers to named policies:
//   - AMD SEV-SNP machines are keyed by the 64-byte CHIP_ID report field
//     (128 lowercase hex chars; Turin hardware IDs are zero-padded)
//   - Intel TDX machines are keyed by the 16-byte PPID (32 lowercase hex
//     chars) carried in the PCK leaf certificate of every quote
//
// Parsing is fail-closed: unknown JSON fields, malformed identifiers,
// dangling policy references, or platform mismatches are errors. A policy
// that cannot be fully enforced must never be partially applied.
package policy

import (
	"fmt"
	"regexp"

	"github.com/tinfoilsh/tinfoil-go/verifier/internal/strictjson"
)

// ArtifactFormat is the required format URI of the platform-endorsements artifact.
const ArtifactFormat = "https://tinfoil.sh/predicate/platform-endorsements/v1"

const (
	// PlatformSEVSNP labels AMD SEV-SNP policies.
	PlatformSEVSNP = "sev-snp"
	// PlatformTDX labels Intel TDX policies.
	PlatformTDX = "tdx"

	sevIdentifierHexLen = 128
	tdxIdentifierHexLen = 32
)

var lowerHexRE = regexp.MustCompile(`^[0-9a-f]+$`)

// Artifact is the parsed platform-endorsements document.
type Artifact struct {
	Format       string                         `json:"format"`
	Measurements map[string]PlatformMeasurement `json:"measurements"`
	Machines     map[string]string              `json:"machines"`
	Policies     map[string]Policy              `json:"policies"`
}

// PlatformMeasurement is one TDX platform configuration's expected registers,
// optionally annotated with the VM shape and host stack it was measured for.
type PlatformMeasurement struct {
	MRTD  string `json:"mrtd"`
	RTMR0 string `json:"rtmr0"`
	Shape *Shape `json:"shape,omitempty"`
	Stack *Stack `json:"stack,omitempty"`
}

// Policy is a named appraisal policy. Exactly one platform block is set,
// matching Platform.
type Policy struct {
	Platform string        `json:"platform"`
	SEVSNP   *SEVSNPPolicy `json:"sev_snp,omitempty"`
	TDX      *TDXPolicy    `json:"tdx,omitempty"`
}

// Parse strictly decodes and validates a platform-endorsements
// artifact. Unknown members anywhere in the document are rejected
// case-sensitively, as are duplicate member names.
func Parse(data []byte) (*Artifact, error) {
	var a Artifact
	if err := strictjson.Unmarshal(data, &a); err != nil {
		return nil, fmt.Errorf("parsing platform-endorsements artifact: %w", err)
	}
	if a.Format != ArtifactFormat {
		return nil, fmt.Errorf("unsupported artifact format %q", a.Format)
	}
	if err := a.validate(); err != nil {
		return nil, err
	}
	return &a, nil
}

func (a *Artifact) validate() error {
	for name, p := range a.Policies {
		switch p.Platform {
		case PlatformSEVSNP:
			if p.SEVSNP == nil || p.TDX != nil {
				return fmt.Errorf("policy %q: platform sev-snp requires exactly the sev_snp block", name)
			}
		case PlatformTDX:
			if p.TDX == nil || p.SEVSNP != nil {
				return fmt.Errorf("policy %q: platform tdx requires exactly the tdx block", name)
			}
			if p.TDX.MinimumTCBEvaluationDataNumber < 0 {
				return fmt.Errorf("policy %q: minimum_tcb_evaluation_data_number must not be negative", name)
			}
			for _, ref := range p.TDX.PlatformMeasurements {
				if _, ok := a.Measurements[ref]; !ok {
					return fmt.Errorf("policy %q: platform_measurements ref %q not in measurements", name, ref)
				}
			}
		default:
			return fmt.Errorf("policy %q: unsupported platform %q", name, p.Platform)
		}
	}

	for identifier, policyName := range a.Machines {
		p, ok := a.Policies[policyName]
		if !ok {
			return fmt.Errorf("machine %s...: unknown policy %q", truncID(identifier), policyName)
		}
		if !lowerHexRE.MatchString(identifier) {
			return fmt.Errorf("machine %s...: identifier is not lowercase hex", truncID(identifier))
		}
		switch p.Platform {
		case PlatformSEVSNP:
			if len(identifier) != sevIdentifierHexLen {
				return fmt.Errorf("machine %s...: sev-snp identifier must be %d hex chars, got %d",
					truncID(identifier), sevIdentifierHexLen, len(identifier))
			}
		case PlatformTDX:
			if len(identifier) != tdxIdentifierHexLen {
				return fmt.Errorf("machine %s...: tdx identifier must be %d hex chars, got %d",
					truncID(identifier), tdxIdentifierHexLen, len(identifier))
			}
		}
	}
	return nil
}

// PolicyFor looks up the appraisal policy for an authenticated platform
// identifier (lowercase hex) extracted from verified evidence, and asserts
// the policy's platform matches the evidence platform. An identifier absent
// from the machines map is an error: the machine is not endorsed.
func (a *Artifact) PolicyFor(identifierHex string, platform string) (string, *Policy, error) {
	name, ok := a.Machines[identifierHex]
	if !ok {
		return "", nil, fmt.Errorf("platform identifier %s... is not endorsed", truncID(identifierHex))
	}
	p := a.Policies[name]
	if p.Platform != platform {
		return "", nil, fmt.Errorf("policy %q is for platform %q, evidence is %q", name, p.Platform, platform)
	}
	return name, &p, nil
}

func truncID(id string) string {
	if len(id) > 16 {
		return id[:16]
	}
	return id
}

// ResolvePlatformMeasurement selects the single measurements-map entry the
// policy allows whose MRTD/RTMR0 equal the quote's authenticated values,
// returning its name. When required is non-nil, only entries measured for
// that VM shape are candidates, so a quote from a machine-endorsed but
// wrong-shaped VM resolves nothing. The measurement inputs must come from a
// verified quote.
func (a *Artifact) ResolvePlatformMeasurement(p *TDXPolicy, required *Shape, mrtdHex, rtmr0Hex string) (string, *PlatformMeasurement, error) {
	anyShapeMatch := false
	for _, ref := range p.PlatformMeasurements {
		m := a.Measurements[ref]
		if required != nil && (m.Shape == nil || !m.Shape.Satisfies(required)) {
			continue
		}
		anyShapeMatch = true
		if m.MRTD == mrtdHex && m.RTMR0 == rtmr0Hex {
			return ref, &m, nil
		}
	}
	if required != nil && !anyShapeMatch {
		return "", nil, fmt.Errorf("no endorsed platform measurement matches the required VM shape %+v", *required)
	}
	return "", nil, fmt.Errorf("platform measurements (mrtd %s...) do not match any allowed configuration", truncID(mrtdHex))
}
