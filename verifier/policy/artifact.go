// Package policy defines what a verified quote is appraised against: which
// machines are endorsed, which platform configurations they may run, and
// the policy each must satisfy. Inputs must come from a verified
// reference-values source; the package itself performs no cryptography.
//
// Parsing is fail-closed: unknown members, malformed identifiers, dangling
// references, or platform mismatches are errors. A policy that cannot be
// fully enforced is never partially applied.
package policy

import (
	"fmt"
	"regexp"

	"github.com/tinfoilsh/tinfoil-go/verifier/internal/strictjson"
)

// ArtifactFormat is the required format URI of the artifact.
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

// Artifact is the parsed policy document: named platform measurements,
// named policies, and the machines map keying both by hardware identity.
type Artifact struct {
	Format       string                         `json:"format"`
	Measurements map[string]PlatformMeasurement `json:"measurements"`
	// Machines maps a machine's hardware identifier to its policy name.
	// SEV-SNP machines are keyed by the 64-byte CHIP_ID (128 lowercase hex
	// chars), TDX machines by the 16-byte PPID (32 lowercase hex chars).
	Machines map[string]string `json:"machines"`
	Policies map[string]Policy `json:"policies"`
}

// PlatformMeasurement is one TDX platform configuration's expected
// registers, annotated with the VM shape it was measured for and,
// optionally, the host stack that produced it.
type PlatformMeasurement struct {
	MRTD  string `json:"mrtd"`
	RTMR0 string `json:"rtmr0"`
	Shape *Shape `json:"shape"`
	// Stack is informational and never checked.
	Stack *Stack `json:"stack,omitempty"`
}

// Policy is a named appraisal policy. Exactly one platform block is set,
// matching Platform.
type Policy struct {
	Platform string        `json:"platform"`
	SEVSNP   *SEVSNPPolicy `json:"sev_snp,omitempty"`
	TDX      *TDXPolicy    `json:"tdx,omitempty"`
}

// Parse strictly decodes and validates a policy artifact. Unknown members
// anywhere in the document are rejected case-sensitively, as are duplicate
// member names.
func Parse(data []byte) (*Artifact, error) {
	var a Artifact
	if err := strictjson.Unmarshal(data, &a); err != nil {
		return nil, fmt.Errorf("parsing policy artifact: %w", err)
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
			if err := p.SEVSNP.Validate(); err != nil {
				return fmt.Errorf("policy %q: %w", name, err)
			}
		case PlatformTDX:
			if p.TDX == nil || p.SEVSNP != nil {
				return fmt.Errorf("policy %q: platform tdx requires exactly the tdx block", name)
			}
			if err := p.TDX.Validate(); err != nil {
				return fmt.Errorf("policy %q: %w", name, err)
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

	for name, m := range a.Measurements {
		if m.Shape == nil {
			return fmt.Errorf("measurement %q: shape is required", name)
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
// returning its name. Only entries measured for the required VM shape are
// candidates, so a quote from a machine-endorsed but wrong-shaped VM
// resolves nothing. The measurement inputs must come from a verified
// quote.
func (a *Artifact) ResolvePlatformMeasurement(p *TDXPolicy, required *Shape, mrtdHex, rtmr0Hex string) (string, *PlatformMeasurement, error) {
	if required == nil {
		return "", nil, fmt.Errorf("required VM shape is missing")
	}
	anyShapeMatch := false
	for _, ref := range p.PlatformMeasurements {
		m := a.Measurements[ref]
		if m.Shape == nil || !m.Shape.Satisfies(required) {
			continue
		}
		anyShapeMatch = true
		if m.MRTD == mrtdHex && m.RTMR0 == rtmr0Hex {
			return ref, &m, nil
		}
	}
	if !anyShapeMatch {
		return "", nil, fmt.Errorf("no endorsed platform measurement matches the required VM shape %+v", *required)
	}
	return "", nil, fmt.Errorf("platform measurements (mrtd %s...) do not match any allowed configuration", truncID(mrtdHex))
}
