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
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	tdxabi "github.com/google/go-tdx-guest/abi"

	"github.com/tinfoilsh/tinfoil-go/document"
	"github.com/tinfoilsh/tinfoil-go/document/collateral"
	"github.com/tinfoilsh/tinfoil-go/internal/errs"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/policy"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/quote/sev"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/quote/tdx"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/runtime"
	"github.com/tinfoilsh/tinfoil-go/verify/measurement"
)

// Authenticated is a signature-verified quote, not yet compared against
// any expected value.
type Authenticated struct {
	platform string
	identity string
	// Measurement is a detached summary of the launch measurement (SEV) or MRTD+RTMRs (TDX).
	Measurement *measurement.Measurement

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
	CodeMeasurement *measurement.Measurement
	// PolicyName is the matched policy name.
	PolicyName string
	// PlatformMeasurementName is the resolved TDX platform configuration;
	// empty for SEV-SNP.
	PlatformMeasurementName string

	quote Authenticated
	sev   *sev.Expectations
	tdx   *tdx.Expectations
}

// ReferenceValues contains authenticated release and platform expectations.
// Config selects config-bound runtime verification; Code and Shape select the
// repository release flow.
type ReferenceValues struct {
	Endorsements *policy.Artifact
	Code         *measurement.Measurement
	Shape        *policy.Shape
	Config       *ConfigReferenceValues
}

type ConfigReferenceValues struct {
	Runtime *runtime.Measurements
	Hash    [sha256.Size]byte
}

// Options carries per-authentication overrides. A nil *Options, and the zero
// value, select the production defaults: the embedded vendor roots and the
// current time. Only the anchor for the document's own platform is used.
//
// The overrides themselves exist only in the conformance build. A production
// binary has no way to set them, so it cannot be made to trust a supplied
// vendor root or to appraise collateral at anything but the current time.
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
// fetches. Callers must assemble a policy and validate before trusting the
// platform.
func Authenticate(ev document.CPUEvidence, en collateral.CPUEndorsements, opts *Options) (result *Authenticated, err error) {
	defer func() { err = errs.WrapAttestation(err) }()
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
		}, opts.sevOptions())
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
		q, err := tdx.Authenticate(tdx.Evidence{Quote: ev.Report, PCS: en.IntelPCS.Responses}, opts.tdxOptions())
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
func Assemble(doc *document.Document, refs ReferenceValues, pins *measurement.Measurement, q *Authenticated) (result *AssembledPolicy, err error) {
	defer func() { err = errs.WrapAttestation(err) }()
	reportData, err := q.reportData(doc)
	if err != nil {
		return nil, err
	}
	return assemble(refs, pins, reportData, q)
}

func (q *Authenticated) reportData(doc *document.Document) ([64]byte, error) {
	reportData, ok := doc.ExpectedReportData()
	if !ok {
		return reportData, &errs.ConfigurationError{Err: fmt.Errorf("a document checked by document.Parse is required")}
	}
	if q == nil {
		return reportData, &errs.ConfigurationError{Err: fmt.Errorf("authenticated quote is required")}
	}
	evidence := doc.CPUEvidence()
	if evidence.Format != q.evidence.Format || !bytes.Equal(evidence.Report, q.evidence.Report) {
		return reportData, &errs.ConfigurationError{Err: fmt.Errorf("authenticated quote is not this document's CPU evidence")}
	}
	return reportData, nil
}

// assemble is Assemble against an explicit REPORT_DATA.
func assemble(refs ReferenceValues, pins *measurement.Measurement, reportData [64]byte, q *Authenticated) (*AssembledPolicy, error) {
	if refs.Endorsements == nil {
		return nil, &errs.ConfigurationError{Err: fmt.Errorf("endorsements are required")}
	}
	if q == nil || q.sev == nil && q.tdx == nil {
		return nil, &errs.ConfigurationError{Err: fmt.Errorf("authenticated quote is required")}
	}
	code := refs.Code
	if refs.Config != nil {
		if code != nil || refs.Shape != nil {
			return nil, &errs.ConfigurationError{Err: fmt.Errorf("config runtime and repository code expectations cannot be combined")}
		}
		runtime := refs.Config.Runtime
		if runtime == nil || runtime.SNPLaunch == nil || runtime.TDXLaunch == nil {
			return nil, fmt.Errorf("complete runtime endorsements are required")
		}
		var err error
		code, err = runtimeMeasurement(runtime, q.platform)
		if err != nil {
			return nil, err
		}
	} else {
		if code == nil {
			return nil, &errs.ConfigurationError{Err: fmt.Errorf("assembling policy: expected code measurement is required")}
		}
		if q.platform == policy.PlatformTDX && refs.Shape == nil {
			return nil, &errs.ConfigurationError{Err: fmt.Errorf("assembling policy: the code artifact's VM shape is required")}
		}
	}
	name, machinePolicy, err := refs.Endorsements.PolicyFor(q.identity, q.platform)
	if err != nil {
		return nil, err
	}
	assembled := &AssembledPolicy{
		CodeMeasurement: code,
		PolicyName:      name,
		quote:           *q,
	}
	var registers []string
	if refs.Config != nil {
		registers, err = applyPins(code.Registers, code.Type, pins)
	} else {
		registers, err = layout(code, pins, q)
	}
	if err != nil {
		return nil, err
	}
	switch q.platform {
	case policy.PlatformSEVSNP:
		p := machinePolicy.SEVSNP
		if refs.Config != nil {
			p, err = refs.Config.resolveSEV(p)
			if err != nil {
				return nil, err
			}
		}
		assembled.sev, err = sev.Assemble(p, q.sev, registers[0], reportData, refs.Config != nil)
	case policy.PlatformTDX:
		var configID *[tdxabi.MrConfigIDSize]byte
		if refs.Config != nil {
			configID = new([tdxabi.MrConfigIDSize]byte)
			copy(configID[:], refs.Config.Hash[:])
		}
		assembled.tdx, assembled.PlatformMeasurementName, err = tdx.Assemble(
			refs.Endorsements, machinePolicy.TDX, refs.Shape, q.tdx, [5]string(registers), reportData, configID)
	default:
		return nil, fmt.Errorf("unsupported platform %q", q.platform)
	}
	if err != nil {
		return nil, err
	}
	return assembled, nil
}

// Validate compares the captured quote against the assembled policy in a
// single vendor library call: no lookups, no translation.
func (p *AssembledPolicy) Validate() (err error) {
	defer func() { err = errs.WrapAttestation(err) }()
	if p == nil || p.sev == nil && p.tdx == nil {
		return &errs.ConfigurationError{Err: fmt.Errorf("assembled policy is required")}
	}
	switch p.quote.platform {
	case policy.PlatformSEVSNP:
		return p.sev.Validate(p.quote.sev)
	case policy.PlatformTDX:
		return p.tdx.Validate(p.quote.tdx)
	default:
		return fmt.Errorf("unsupported platform %q", p.quote.platform)
	}
}

// layout maps code and pins to enclave registers, leaving platform defaults empty.
func layout(code, pins *measurement.Measurement, q *Authenticated) ([]string, error) {
	if code.Type != measurement.SnpTdxMultiPlatformV1 || len(code.Registers) != 3 {
		return nil, fmt.Errorf("code measurement is %s with %d registers, want %s with 3", code.Type, len(code.Registers), measurement.SnpTdxMultiPlatformV1)
	}
	registers := []string{code.Registers[0]}
	enclaveType := measurement.SevGuestV2
	if q.platform == policy.PlatformTDX {
		registers = []string{"", "", code.Registers[1], code.Registers[2], ""}
		enclaveType = measurement.TdxGuestV2
	}
	return applyPins(registers, enclaveType, pins)
}

func applyPins(registers []string, enclaveType measurement.PredicateType, pins *measurement.Measurement) ([]string, error) {
	if err := measurement.ValidatePins(pins); err != nil {
		return nil, &errs.ConfigurationError{Err: err}
	}
	if pins == nil {
		return registers, nil
	}
	if pins.Type != enclaveType || len(pins.Registers) != len(registers) {
		return nil, fmt.Errorf("pinned measurement is %s with %d registers, enclave is %s with %d", pins.Type, len(pins.Registers), enclaveType, len(registers))
	}
	for i, pin := range pins.Registers {
		if pin != "" && registers[i] != "" && !strings.EqualFold(registers[i], pin) {
			return nil, fmt.Errorf("pinned register %d does not match the signed release measurement", i)
		}
		registers[i] = cmp.Or(registers[i], pin)
	}
	return registers, nil
}

func runtimeMeasurement(runtime *runtime.Measurements, platform string) (*measurement.Measurement, error) {
	switch platform {
	case policy.PlatformSEVSNP:
		return &measurement.Measurement{Type: measurement.SevGuestV2, Registers: []string{runtime.SNPLaunch.Measurement}}, nil
	case policy.PlatformTDX:
		registers := runtime.TDXLaunch.Registers()
		return &measurement.Measurement{Type: measurement.TdxGuestV2, Registers: registers[:]}, nil
	default:
		return nil, fmt.Errorf("unsupported platform %q", platform)
	}
}

func (c *ConfigReferenceValues) resolveSEV(p *policy.SEVSNPPolicy) (*policy.SEVSNPPolicy, error) {
	if p == nil || p.ConfigBinding != policy.ConfigBindingSHA256 {
		return nil, fmt.Errorf("config verification requires a config-binding platform policy")
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	resolved := *p
	resolved.ConfigBinding = ""
	resolved.HostData = hex.EncodeToString(c.Hash[:])
	return &resolved, nil
}
