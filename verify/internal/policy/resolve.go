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
// needs no knowledge of IGVM at all.
//
// A cvmimage launch measurement depends only on the image, so the config
// cannot be measured and the endorsements cannot enumerate one platform
// measurement per machine shape. A policy declaring config_binding is an
// expectation with a hole in it; this fills the hole.
//
// Every policy must declare a binding, so a legacy artifact cannot be resolved
// and a mixed one cannot be partly resolved. That, and assembly's refusal of a
// binding that was never resolved, are what keep the two artifacts from
// standing in for each other.
func (a *Artifact) Resolve(configDigest string) (*Artifact, error) {
	if err := validatePolicyHex("config digest", configDigest, 32); err != nil {
		return nil, err
	}
	// Only Policies is cloned, and only its blocks are rewritten; Measurements
	// and Machines are shared with the authenticated source and must stay
	// read-only. Parse is the only constructor on the real path, so each
	// policy already carries exactly its platform's block — the nil checks
	// below mean an artifact built any other way fails rather than panics.
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
			// MRCONFIGID is 48 bytes: the digest, then the 16 zero bytes a
			// launch writes after a 32-byte hash.
			tdx.ConfigBinding, tdx.MRConfigID = "", configDigest+strings.Repeat("0", 32)
			p.TDX = &tdx
		default:
			return nil, fmt.Errorf("policy %q declares no config_binding", name)
		}
		resolved.Policies[name] = p
	}
	return &resolved, nil
}
