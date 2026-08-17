//go:build tinfoil_conformance

// Package conformance is the tinfoil-go v3 conformance adapter: it runs shared
// cross-SDK fixtures against the verifier and reports the result in the
// language-neutral wire contract below. Every SDK implements the same
// Input/Output shapes and exit codes so the suite drives them identically.
//
// The full-verify stage composes the verification flow step by step (rather
// than calling client.VerifyDocumentV3) so it can inject synthetic roots via
// the tag-gated seams, pin the freshness appraisal time for frozen documents,
// and attribute a rejection to the failing layer — all with no production
// change beyond those seams.
package conformance

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/tinfoilsh/tinfoil-go/verifier/envelope"
	"github.com/tinfoilsh/tinfoil-go/verifier/measurement"
	"github.com/tinfoilsh/tinfoil-go/verifier/provenance"
	"github.com/tinfoilsh/tinfoil-go/verifier/quote"
	"github.com/tinfoilsh/tinfoil-go/verifier/quote/sev"
	"github.com/tinfoilsh/tinfoil-go/verifier/quote/tdx"
)

// Exit codes are the cross-SDK adapter contract: the suite reads them to decide
// pass/skip and never depends on stdout for the verdict.
const (
	ExitAccepted    = 0  // verification accepted; Output.Outputs populated
	ExitInternal    = 1  // unexpected adapter error
	ExitRejected    = 10 // verification rejected; Output.Rejection populated
	ExitUnsupported = 20 // stage/capability not supported by this SDK
	ExitMalformed   = 30 // input did not parse
)

// Stages this adapter handles. The full stage runs the whole flow including
// freshness; the block stages isolate a single layer.
const (
	StageVerify                 = "verify-attestation-v3"      // full envelope→provenance→freshness→quote→policy
	StageCheckEnvelope          = "v3-check-envelope"          // strict parse + nonce/hash/report-data binding
	StageAuthenticateProvenance = "v3-authenticate-provenance" // sigstore-code identity + measurement
	StageAssemblePolicy         = "v3-assemble-policy"         // sigstore-platform endorsements artifact
	StageAuthenticateQuote      = "v3-authenticate-quote"      // CPU quote signature chain to the vendor root
)

// Input is the stdin JSON: a v3 document, the verifier-supplied nonce, the
// pinned repo, and the synthetic roots it was produced under. Empty root fields
// select the embedded production roots (so real-frozen fixtures need none).
type Input struct {
	SchemaVersion string `json:"schema_version"`
	DocumentB64   string `json:"document_b64"`
	NonceHex      string `json:"nonce_hex"`
	Repo          string `json:"repo"`

	// AMD SEV-SNP anchor, supplied as the ARK plus its ASK (KDS convention).
	AMDRootCAPEM string `json:"amd_root_ca_pem,omitempty"`
	ASKPEM       string `json:"ask_pem,omitempty"`
	// Intel TDX anchor.
	IntelSGXRootPEM string `json:"intel_sgx_root_pem,omitempty"`
	// Sigstore trusted-root document, base64 (JSON bytes).
	SigstoreTrustedRootB64 string `json:"sigstore_trusted_root_json_b64,omitempty"`

	// VerificationTimeUnix pins the validity-window and freshness-appraisal
	// clock so a frozen document replays at its capture time; 0 uses the
	// current time.
	VerificationTimeUnix int64 `json:"verification_time_unix,omitempty"`
}

// Output is the stdout JSON. Exactly one of Outputs / Rejection is set.
type Output struct {
	Stage     string         `json:"stage"`
	Accepted  bool           `json:"accepted"`
	Outputs   *AcceptOutputs `json:"outputs,omitempty"`
	Rejection *Rejection     `json:"rejection,omitempty"`
}

// AcceptOutputs are the verified facts, in a shape every SDK can produce and
// the suite can diff for cross-SDK equivalence.
type AcceptOutputs struct {
	CodeDigest         string      `json:"code_digest,omitempty"`
	CodeMeasurement    Measurement `json:"code_measurement,omitzero"`
	EnclaveMeasurement Measurement `json:"enclave_measurement,omitzero"`
	// Endorsed channel keys the caller binds its connection to: the TLS SPKI
	// fingerprint and HPKE public key, hash-bound into the quote. Recovering
	// these is the point of verification, so every SDK must surface them.
	TLSPublicKeyFP string `json:"tls_public_key_fp,omitempty"`
	HPKEPublicKey  string `json:"hpke_public_key,omitempty"`
}

// Measurement mirrors verifier/measurement.Measurement as plain JSON.
type Measurement struct {
	Type      string   `json:"type"`
	Registers []string `json:"registers"`
}

// Rejection carries a coarse, layer-tagged code, stable across SDKs.
type Rejection struct {
	Code string `json:"code"`
}

// Run executes one stage and returns the wire Output plus the adapter exit code.
//
// Run is single-call by contract: it pins process-wide seams (verification
// clock, injected roots) for the duration of the call and restores them on
// return. The adapter binary and the fixture runner invoke it sequentially;
// it must not be called concurrently.
func Run(stage string, in Input) (Output, int) {
	// Pin the validity-window and freshness clock for a frozen document.
	appraisal := time.Now()
	if in.VerificationTimeUnix != 0 {
		appraisal = time.Unix(in.VerificationTimeUnix, 0)
		sev.SetVerificationTime(appraisal)
		tdx.SetVerificationTime(appraisal)
		defer sev.ResetVerificationTime()
		defer tdx.ResetVerificationTime()
	}

	if in.SchemaVersion != SchemaVersion {
		return malformed(stage, fmt.Errorf("schema_version %q, want %q", in.SchemaVersion, SchemaVersion))
	}
	doc, err := base64.StdEncoding.DecodeString(in.DocumentB64)
	if err != nil {
		return malformed(stage, fmt.Errorf("document_b64: %w", err))
	}
	nonce, err := hex.DecodeString(in.NonceHex)
	if err != nil {
		return malformed(stage, fmt.Errorf("nonce_hex: %w", err))
	}
	rts, err := in.roots()
	if err != nil {
		return malformed(stage, err)
	}
	prov, err := newProvAuth(rts.sigstore)
	if err != nil {
		return malformed(stage, err)
	}

	switch stage {
	case StageVerify:
		return verifyFull(doc, nonce, in.Repo, rts, prov, appraisal)
	case StageCheckEnvelope:
		if _, _, err := envelope.Check(doc, nonce); err != nil {
			return reject(stage, "ENVELOPE_REJECTED")
		}
		return Output{Stage: stage, Accepted: true}, ExitAccepted
	case StageAuthenticateProvenance:
		parsed, err := envelope.Parse(doc)
		if err != nil {
			return malformed(stage, fmt.Errorf("envelope: %w", err))
		}
		codeRef, err := parsed.ReferenceValuesCollateral(envelope.CollateralSigstoreCodeV1Format)
		if err != nil {
			return reject(stage, "PROVENANCE_REJECTED")
		}
		code, err := prov.code(codeRef.SigstoreBundle, in.Repo, codeRef.Tag, codeRef.Digest)
		if err != nil {
			return reject(stage, "PROVENANCE_REJECTED")
		}
		return Output{Stage: stage, Accepted: true, Outputs: &AcceptOutputs{
			CodeDigest:      code.Digest,
			CodeMeasurement: toMeasurement(code.Measurement),
		}}, ExitAccepted
	case StageAssemblePolicy:
		parsed, err := envelope.Parse(doc)
		if err != nil {
			return malformed(stage, fmt.Errorf("envelope: %w", err))
		}
		platRef, err := parsed.ReferenceValuesCollateral(envelope.CollateralSigstorePlatformV1Format)
		if err != nil {
			return reject(stage, "PROVENANCE_REJECTED")
		}
		if _, err := prov.platform(platRef.SigstoreBundle, platRef.Repo, platRef.Tag, platRef.Digest); err != nil {
			return reject(stage, "PROVENANCE_REJECTED")
		}
		return Output{Stage: stage, Accepted: true}, ExitAccepted
	case StageAuthenticateQuote:
		parsed, err := envelope.Parse(doc)
		if err != nil {
			return malformed(stage, fmt.Errorf("envelope: %w", err))
		}
		undo, err := setQuoteRoots(rts)
		if err != nil {
			return malformed(stage, err)
		}
		defer undo()
		auth, err := quote.Authenticate(parsed)
		if err != nil {
			return reject(stage, "QUOTE_REJECTED")
		}
		return Output{Stage: stage, Accepted: true, Outputs: &AcceptOutputs{
			EnclaveMeasurement: toMeasurement(auth.Measurement),
		}}, ExitAccepted
	default:
		return Output{Stage: stage}, ExitUnsupported
	}
}

// verifyFull composes the whole flow; the first failing step names the layer.
func verifyFull(doc, nonce []byte, repo string, rts roots, prov provAuth, appraisal time.Time) (Output, int) {
	parsed, reportData, err := envelope.Check(doc, nonce)
	if err != nil {
		return reject(StageVerify, "ENVELOPE_REJECTED")
	}
	code, endorsements, err := authReferenceValues(parsed, repo, prov, appraisal)
	if err != nil {
		return reject(StageVerify, "PROVENANCE_REJECTED")
	}
	undo, err := setQuoteRoots(rts)
	if err != nil {
		return malformed(StageVerify, err)
	}
	defer undo()
	auth, err := quote.Authenticate(parsed)
	if err != nil {
		return reject(StageVerify, "QUOTE_REJECTED")
	}
	assembled, err := quote.Assemble(endorsements.Artifact, code.Measurement, code.Shape, reportData, auth)
	if err != nil {
		return reject(StageVerify, "POLICY_REJECTED")
	}
	if err := assembled.Validate(); err != nil {
		return reject(StageVerify, "POLICY_REJECTED")
	}
	// A document that verifies but endorses no usable channel keys is useless
	// to every real client (SecureClient rejects at binding), so the full
	// stage requires both — mirroring the deployed end-to-end behavior.
	tlsFP, hpke := boundKeys(parsed)
	if tlsFP == "" || hpke == "" {
		return reject(StageVerify, "ENVELOPE_REJECTED")
	}
	return Output{Stage: StageVerify, Accepted: true, Outputs: &AcceptOutputs{
		CodeDigest:         code.Digest,
		CodeMeasurement:    toMeasurement(code.Measurement),
		EnclaveMeasurement: toMeasurement(auth.Measurement),
		TLSPublicKeyFP:     tlsFP,
		HPKEPublicKey:      hpke,
	}}, ExitAccepted
}

// boundKeys returns the endorsed TLS SPKI fingerprint and HPKE public key from
// the verified crypto material (hash-bound into the quote via envelope.Check).
func boundKeys(doc *envelope.Document) (tlsFP, hpke string) {
	for _, it := range doc.CryptoMaterialItems() {
		switch {
		case it.ID == envelope.CryptoMaterialIDTLS && it.Format == envelope.KeySPKIFPSHA256V1Format:
			tlsFP = it.Data
		case it.ID == envelope.CryptoMaterialIDHPKE && it.Format == envelope.KeyX25519HPKEV1Format:
			hpke = it.Data
		}
	}
	return
}

// authReferenceValues authenticates the code and platform artifacts and their
// freshness proofs, mirroring the production reference-values step.
func authReferenceValues(doc *envelope.Document, repo string, prov provAuth, appraisal time.Time) (*provenance.Code, *provenance.PlatformEndorsements, error) {
	codeRef, err := doc.ReferenceValuesCollateral(envelope.CollateralSigstoreCodeV1Format)
	if err != nil {
		return nil, nil, err
	}
	code, err := prov.code(codeRef.SigstoreBundle, repo, codeRef.Tag, codeRef.Digest)
	if err != nil {
		return nil, nil, err
	}
	codeFresh, err := doc.FreshnessCollateral(envelope.FreshnessCollateralIDCode)
	if err != nil {
		return nil, nil, err
	}
	if _, err := prov.freshness(codeFresh.SigstoreBundle, &code.AuthenticatedArtifact, appraisal); err != nil {
		return nil, nil, err
	}
	platRef, err := doc.ReferenceValuesCollateral(envelope.CollateralSigstorePlatformV1Format)
	if err != nil {
		return nil, nil, err
	}
	endorsements, err := prov.platform(platRef.SigstoreBundle, platRef.Repo, platRef.Tag, platRef.Digest)
	if err != nil {
		return nil, nil, err
	}
	platFresh, err := doc.FreshnessCollateral(envelope.FreshnessCollateralIDPlatform)
	if err != nil {
		return nil, nil, err
	}
	if _, err := prov.freshness(platFresh.SigstoreBundle, &endorsements.AuthenticatedArtifact, appraisal); err != nil {
		return nil, nil, err
	}
	return code, endorsements, nil
}

// roots are the injected synthetic anchors; a nil field selects the embedded
// production root.
type roots struct {
	amd      []byte // ASK+ARK KDS chain
	intel    []byte // Intel SGX root PEM
	sigstore []byte // Sigstore trusted-root JSON
}

func (in Input) roots() (roots, error) {
	var r roots
	switch {
	case in.AMDRootCAPEM != "" && in.ASKPEM != "":
		// KDS cert_chain is ASK then ARK.
		r.amd = []byte(strings.TrimSpace(in.ASKPEM) + "\n" + strings.TrimSpace(in.AMDRootCAPEM) + "\n")
	case in.AMDRootCAPEM != "" || in.ASKPEM != "":
		return r, fmt.Errorf("amd_root_ca_pem and ask_pem must be supplied together")
	}
	if in.IntelSGXRootPEM != "" {
		r.intel = []byte(in.IntelSGXRootPEM)
	}
	if in.SigstoreTrustedRootB64 != "" {
		j, err := base64.StdEncoding.DecodeString(in.SigstoreTrustedRootB64)
		if err != nil {
			return r, fmt.Errorf("sigstore_trusted_root_json_b64: %w", err)
		}
		r.sigstore = j
	}
	return r, nil
}

// setQuoteRoots injects the vendor roots for quote.Authenticate and returns an
// undo that restores the embedded roots.
func setQuoteRoots(rts roots) (func(), error) {
	var undo []func()
	reset := func() {
		for i := len(undo) - 1; i >= 0; i-- {
			undo[i]()
		}
	}
	if rts.amd != nil {
		sev.SetAMDRoot(rts.amd)
		undo = append(undo, sev.ResetAMDRoot)
	}
	if rts.intel != nil {
		if err := tdx.SetIntelRoot(rts.intel); err != nil {
			reset()
			return nil, err
		}
		undo = append(undo, tdx.ResetIntelRoot)
	}
	return reset, nil
}

// provAuth authenticates provenance against an injected Sigstore root, or the
// embedded root when none was supplied. The package functions and the
// per-client methods share signatures, so this is just method-value binding.
type provAuth struct {
	code      func(bundleJSON []byte, repo, tag, hexDigest string) (*provenance.Code, error)
	platform  func(bundleJSON []byte, repo, tag, hexDigest string) (*provenance.PlatformEndorsements, error)
	freshness func(bundleJSON []byte, expected *provenance.AuthenticatedArtifact, now time.Time) (time.Time, error)
}

func newProvAuth(sigstoreRootJSON []byte) (provAuth, error) {
	if sigstoreRootJSON == nil {
		return provAuth{provenance.AuthenticateCode, provenance.AuthenticatePlatformEndorsements, provenance.AuthenticateFreshness}, nil
	}
	c, err := provenance.NewClientFromJSON(sigstoreRootJSON)
	if err != nil {
		return provAuth{}, fmt.Errorf("sigstore_trusted_root_json_b64: %w", err)
	}
	return provAuth{c.AuthenticateCode, c.AuthenticatePlatformEndorsements, c.AuthenticateFreshness}, nil
}

func toMeasurement(m *measurement.Measurement) Measurement {
	if m == nil {
		return Measurement{}
	}
	return Measurement{Type: string(m.Type), Registers: m.Registers}
}

func reject(stage, code string) (Output, int) {
	return Output{Stage: stage, Accepted: false, Rejection: &Rejection{Code: code}}, ExitRejected
}

func malformed(stage string, _ error) (Output, int) {
	return Output{Stage: stage, Accepted: false, Rejection: &Rejection{Code: "MALFORMED_INPUT"}}, ExitMalformed
}
