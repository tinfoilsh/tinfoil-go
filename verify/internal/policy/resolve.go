package policy

import (
	"fmt"
	"maps"
	"strings"
)

// ConfigBindingSHA256 is the only config binding this verifier implements: the
// launch register holds SHA-256 of the approved config bytes.
const ConfigBindingSHA256 = "sha256"

// Resolve returns a copy of a in which every policy's config binding has been
// turned into the register the launch must report, so that policy assembly
// needs no knowledge of IGVM. Every policy must declare a binding: a legacy
// artifact cannot be resolved, and a mixed one cannot be partly resolved.
func (a *Artifact) Resolve(configDigest string) (*Artifact, error) {
	if err := validatePolicyHex("config digest", configDigest, 32); err != nil {
		return nil, err
	}
	// Only Policies is cloned; Measurements and Machines are shared with the
	// authenticated source and must stay read-only. The nil checks below mean
	// an artifact that did not come from Parse fails rather than panics.
	resolved := *a
	resolved.Policies = maps.Clone(a.Policies)
	for name, p := range resolved.Policies {
		switch {
		case p.SEVSNP != nil && p.SEVSNP.ConfigBinding != "":
			sev := *p.SEVSNP
			sev.ConfigBinding, sev.HostData = "", configDigest
			p.SEVSNP = &sev
		case p.TDX != nil && p.TDX.ConfigBinding != "":
			tdx := *p.TDX
			// MRCONFIGID is 48 bytes: the digest then 16 zero bytes.
			tdx.ConfigBinding, tdx.MRConfigID = "", configDigest+strings.Repeat("0", 32)
			p.TDX = &tdx
		default:
			return nil, fmt.Errorf("policy %q declares no config_binding", name)
		}
		resolved.Policies[name] = p
	}
	return &resolved, nil
}
