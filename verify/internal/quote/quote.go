// Package quote verifies a v3 document's CPU evidence in three phases:
//
//  1. Authenticate: verify the quote's signature chain up to the pinned
//     vendor root, from document-carried collateral only. Authenticated,
//     not yet appraised.
//  2. Assemble: resolve the complete policy — every value the quote must
//     attest, as one object. Entries differ only in which verified source
//     resolves them (policy artifact, code provenance, document); that
//     distinction ends here. Assembly fails if any entry cannot be
//     resolved.
//  3. Validate: one comparison of the quote against the assembled policy,
//     inside the vendor library's validation options.
package quote

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	tdxabi "github.com/google/go-tdx-guest/abi"

	"github.com/tinfoilsh/tinfoil-go/verify/document"
	"github.com/tinfoilsh/tinfoil-go/verify/document/collateral"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/policy"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/quote/sev"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/quote/tdx"
	"github.com/tinfoilsh/tinfoil-go/verify/measurement"
)

// Authenticated is a signature-verified quote, not yet compared against
// any expected value.
type Authenticated struct {
	platform string
	identity string
	// Measurement is the authenticated launch measurement (SEV) or MRTD and RTMRs (TDX).
	Measurement measurement.Measurement

	// evidence is the CPU evidence that was authenticated, so Assemble can
	// check it appraises the quote against the document it came from.
	evidence document.CPUEvidence
	sev      *sev.Quote
	tdx      *tdx.Quote
}

// Platform is policy.PlatformSEVSNP or policy.PlatformTDX.
func (q *Authenticated) Platform() string { return q.platform }

// Identity is the authenticated machine identifier (SEV CHIP_ID / TDX PPID), lowercase hex.
func (q *Authenticated) Identity() string { return q.identity }

// AssembledPolicy is the complete expected state of a quote, fully
// resolved before validation runs. It captures the quote it was assembled
// for, so it cannot be applied to any other quote.
type AssembledPolicy struct {
	// CodeMeasurement is the registers the release fixes on the quote's platform.
	CodeMeasurement measurement.Expected
	// PolicyName is the matched policy name.
	PolicyName string
	// PlatformMeasurementName is the resolved TDX platform configuration;
	// empty for SEV-SNP.
	PlatformMeasurementName string

	quote Authenticated
	sev   *sev.Expectations
	tdx   *tdx.Expectations
}

// ReferenceValues prepares authenticated inputs for a specific verification contract.
// Implementations resolve all workload expectations before shared assembly.
type ReferenceValues interface {
	resolve(*Authenticated, measurement.Expected) (*resolvedValues, error)
}

type resolvedValues struct {
	policy                  *policy.Policy
	policyName              string
	platformMeasurementName string
	code                    measurement.Expected // the registers the release fixes
	expected                measurement.Expected // code plus pins and, for legacy TDX, platform registers
	hostData                string
	configID                [tdxabi.MrConfigIDSize]byte
}

// Options carries per-authentication overrides. A nil *Options, and the zero
// value, select the production default: the embedded vendor roots. Only the
// anchor for the document's own platform is used.
//
// The overrides themselves exist only in the conformance build. A production
// binary has no way to set them, so it cannot be made to trust a supplied
// vendor root.
type Options struct {
	overrides overrides
}

func (o *Options) sevOptions() *sev.Options {
	if o == nil {
		return nil
	}
	return o.overrides.sev()
}

func (o *Options) tdxOptions() *tdx.Options {
	if o == nil {
		return nil
	}
	return o.overrides.tdx()
}

// Authenticate verifies the evidence's signature chain up to the pinned
// vendor root, from the supplied endorsement collateral alone — no network
// fetches. Certificate and CRL validity windows are appraised at now, the
// instant the caller judges the rest of the document against; this layer
// never reads the clock. Callers must assemble a policy and validate before
// trusting the platform.
func Authenticate(ev document.CPUEvidence, en collateral.CPUEndorsements, now time.Time, opts *Options) (result *Authenticated, err error) {
	switch ev.Format {
	case document.SEVSNPReportV1Format:
		// v3 is single-request: missing collateral is rejected, never
		// patched up with a network fetch.
		if en.AMDVCEK == nil {
			return nil, fmt.Errorf("no amd-vcek endorsement collateral for the cpu")
		}
		if en.AMDCRL == nil {
			return nil, fmt.Errorf("no amd-crl endorsement collateral for the cpu")
		}
		q, err := sev.Authenticate(sev.Evidence{
			Report:       ev.Report,
			VCEKDER:      en.AMDVCEK.VCEKDER,
			CertChainPEM: en.AMDVCEK.CertChainPEM,
			CRLDER:       en.AMDCRL.CRLDER,
		}, now, opts.sevOptions())
		if err != nil {
			return nil, err
		}
		return &Authenticated{
			platform:    policy.PlatformSEVSNP,
			identity:    q.Identity(),
			Measurement: q.Measurement,
			evidence:    ev.Clone(),
			sev:         q,
		}, nil
	case document.TDXQuoteV1Format:
		if en.IntelPCS == nil {
			return nil, fmt.Errorf("no intel-pcs endorsement collateral for the cpu")
		}
		q, err := tdx.Authenticate(tdx.Evidence{Quote: ev.Report, PCS: en.IntelPCS.Responses}, now, opts.tdxOptions())
		if err != nil {
			return nil, err
		}
		return &Authenticated{
			platform:    policy.PlatformTDX,
			identity:    q.Identity(),
			Measurement: q.Measurement,
			evidence:    ev.Clone(),
			tdx:         q,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported cpu_evidence format %q", ev.Format)
	}
}

// Assemble combines endorsed machine policy, release measurements, caller pins,
// and the REPORT_DATA doc binds. TDX platform measurements must match the
// required VM shape. A machine absent from endorsements is rejected. Pins fill
// unset registers or must match the existing source value.
//
// doc must come from document.Parse, so its expected REPORT_DATA was
// recomputed from the caller's nonce, and q must be the quote authenticated
// from doc's own CPU evidence: a quote cannot be appraised against another
// document's challenge.
func Assemble(doc *document.Document, refs ReferenceValues, pins measurement.Expected, q *Authenticated) (result *AssembledPolicy, err error) {
	reportData, err := q.reportData(doc)
	if err != nil {
		return nil, err
	}
	return assemble(refs, pins, reportData, q)
}

func (q *Authenticated) reportData(doc *document.Document) ([64]byte, error) {
	// Both checks bind the quote to the caller's challenge. verify never
	// fails them, so failing one is an SDK bug, and the document is rejected.
	reportData, ok := doc.ExpectedReportData()
	if !ok {
		return reportData, fmt.Errorf("a document checked by document.Parse is required")
	}
	evidence := doc.CPUEvidence()
	if evidence.Format != q.evidence.Format || !bytes.Equal(evidence.Report, q.evidence.Report) {
		return reportData, fmt.Errorf("authenticated quote is not this document's CPU evidence")
	}
	return reportData, nil
}

// assemble is Assemble against an explicit REPORT_DATA.
func assemble(refs ReferenceValues, pins measurement.Expected, reportData [64]byte, q *Authenticated) (*AssembledPolicy, error) {
	resolved, err := refs.resolve(q, pins)
	if err != nil {
		return nil, err
	}
	expected, err := complete(resolved.expected)
	if err != nil {
		return nil, err
	}
	assembled := &AssembledPolicy{
		CodeMeasurement:         resolved.code,
		PolicyName:              resolved.policyName,
		PlatformMeasurementName: resolved.platformMeasurementName,
		quote:                   *q,
	}
	switch m := expected.(type) {
	case measurement.SEVSNP:
		if q.platform != policy.PlatformSEVSNP {
			return nil, fmt.Errorf("expected an SEV-SNP measurement for a %s quote", q.platform)
		}
		p := *resolved.policy.SEVSNP
		p.HostData = resolved.hostData
		assembled.sev, err = sev.Assemble(&p, q.sev, m.Launch, reportData)
	case measurement.TDX:
		if q.platform != policy.PlatformTDX {
			return nil, fmt.Errorf("expected a TDX measurement for a %s quote", q.platform)
		}
		assembled.tdx, err = tdx.Assemble(resolved.policy.TDX, q.tdx, m, reportData, resolved.configID)
	}
	if err != nil {
		return nil, err
	}
	return assembled, nil
}

// Validate compares the captured quote against the assembled policy in a
// single vendor library call: no lookups, no translation.
func (p *AssembledPolicy) Validate() (err error) {
	switch p.quote.platform {
	case policy.PlatformSEVSNP:
		return p.sev.Validate(p.quote.sev)
	case policy.PlatformTDX:
		return p.tdx.Validate(p.quote.tdx)
	default:
		return fmt.Errorf("unsupported platform %q", p.quote.platform)
	}
}

func resolvePolicy(endorsements *policy.Artifact, q *Authenticated) (*resolvedValues, error) {
	name, p, err := endorsements.PolicyFor(q.identity, q.platform)
	if err != nil {
		return nil, err
	}
	return &resolvedValues{policy: p, policyName: name}, nil
}

// applyPins fills the registers the code leaves open from the pins, and
// requires every pin the code also fixes to agree with it. code is for the
// enclave's platform, and pins for the other platform reject.
func applyPins(code measurement.Expected, platform string, pins measurement.Expected) (measurement.Expected, error) {
	if pins == nil {
		return code, nil
	}
	var err error
	fill := func(name string, fixed, pin *measurement.Register) *measurement.Register {
		switch {
		case pin == nil:
			return fixed
		case fixed == nil:
			return pin
		case *fixed != *pin && err == nil:
			err = fmt.Errorf("pinned %s does not match the signed release measurement", name)
		}
		return fixed
	}
	var merged measurement.Expected
	switch p := pins.(type) {
	case measurement.ExpectedSEVSNP:
		c, ok := code.(measurement.ExpectedSEVSNP)
		if !ok {
			return nil, fmt.Errorf("pinned registers are for %s, but the enclave is %s", policy.PlatformSEVSNP, platform)
		}
		merged = measurement.ExpectedSEVSNP{Launch: fill("launch measurement", c.Launch, p.Launch)}
	case measurement.ExpectedTDX:
		c, ok := code.(measurement.ExpectedTDX)
		if !ok {
			return nil, fmt.Errorf("pinned registers are for %s, but the enclave is %s", policy.PlatformTDX, platform)
		}
		merged = measurement.ExpectedTDX{
			MRTD:  fill("MRTD", c.MRTD, p.MRTD),
			RTMR0: fill("RTMR0", c.RTMR0, p.RTMR0),
			RTMR1: fill("RTMR1", c.RTMR1, p.RTMR1),
			RTMR2: fill("RTMR2", c.RTMR2, p.RTMR2),
			RTMR3: fill("RTMR3", c.RTMR3, p.RTMR3),
		}
	default:
		return nil, fmt.Errorf("unsupported pinned measurement %T", pins)
	}
	if err != nil {
		return nil, err
	}
	return merged, nil
}

// complete returns the measurement e requires, failing if any register is
// still unconstrained: assembly never leaves a register unchecked.
func complete(e measurement.Expected) (measurement.Measurement, error) {
	var missing []string
	get := func(name string, r *measurement.Register) measurement.Register {
		if r == nil {
			missing = append(missing, name)
			return measurement.Register{}
		}
		return *r
	}
	var m measurement.Measurement
	switch e := e.(type) {
	case measurement.ExpectedSEVSNP:
		m = measurement.SEVSNP{Launch: get("launch measurement", e.Launch)}
	case measurement.ExpectedTDX:
		m = measurement.TDX{
			MRTD:  get("MRTD", e.MRTD),
			RTMR0: get("RTMR0", e.RTMR0),
			RTMR1: get("RTMR1", e.RTMR1),
			RTMR2: get("RTMR2", e.RTMR2),
			RTMR3: get("RTMR3", e.RTMR3),
		}
	default:
		return nil, fmt.Errorf("unsupported expected measurement %T", e)
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("nothing fixes the expected %s", strings.Join(missing, ", "))
	}
	return m, nil
}
