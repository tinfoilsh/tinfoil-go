//go:build tinfoil_conformance

// Package conformance is the tinfoil-go v3 conformance adapter: it runs shared
// cross-SDK fixtures against the verifier and reports the result in the
// language-neutral wire contract below. Every SDK implements the same
// Input/Output shapes and exit codes so the suite drives them identically.
//
// The full-verify stage drives the layers itself rather than making one
// VerifyV3 call, because a rejection has to name the layer that produced it
// and a single call yields a single error. The reference-values step is not
// its own: it goes through verifier.Verifier, so the shared fixtures appraise
// the code that production runs. The remaining steps are direct calls into the
// same document and quote packages the verifier uses.
//
// Synthetic roots and the appraisal clock travel as ordinary per-call options,
// so the adapter mutates no production state.
package conformance

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/tinfoilsh/tinfoil-go/verifier"
	"github.com/tinfoilsh/tinfoil-go/verifier/document"
	"github.com/tinfoilsh/tinfoil-go/verifier/measurement"
	"github.com/tinfoilsh/tinfoil-go/verifier/provenance"
	"github.com/tinfoilsh/tinfoil-go/verifier/quote"
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

// Output is the stdout JSON. Rejection is present iff Accepted is false;
// Outputs is present on accepts that carry verified facts (block-stage
// accepts may carry neither).
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
	// ChannelBinding is set by the live-verify integration lane after the
	// live transport key was matched against the endorsed one.
	ChannelBinding string `json:"channel_binding,omitempty"`
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
// The verification clock and the injected vendor roots travel as per-call
// options, so Run holds no process state and concurrent calls cannot observe
// each other.
func Run(stage string, in Input) (Output, int) {
	// Pin the validity-window and freshness clock for a frozen document.
	appraisal := time.Now()
	if in.VerificationTimeUnix != 0 {
		appraisal = time.Unix(in.VerificationTimeUnix, 0)
	}

	if in.SchemaVersion != SchemaVersion {
		return malformed(stage)
	}
	doc, err := base64.StdEncoding.DecodeString(in.DocumentB64)
	if err != nil {
		return malformed(stage)
	}
	nonce, err := hex.DecodeString(in.NonceHex)
	if err != nil {
		return malformed(stage)
	}
	rts, err := in.roots()
	if err != nil {
		return malformed(stage)
	}
	prov, err := newProvClient(rts.sigstore)
	if err != nil {
		return malformed(stage)
	}
	quoteOpts := &quote.Options{}
	quoteOpts.DangerousTestOnlySetClock(appraisal)
	quoteOpts.DangerousTestOnlySetRoots(rts.amd, rts.intel)
	core, err := verifier.New(
		verifier.DangerousTestOnlyWithClock(func() time.Time { return appraisal }),
		verifier.DangerousTestOnlyWithSigstoreRoot(rts.sigstore),
	)
	if err != nil {
		return malformed(stage)
	}

	switch stage {
	case StageVerify:
		return verifyFull(doc, nonce, in.Repo, quoteOpts, core)
	case StageCheckEnvelope:
		if _, _, err := document.Check(doc, nonce); err != nil {
			return reject(stage, "ENVELOPE_REJECTED")
		}
		return Output{Stage: stage, Accepted: true}, ExitAccepted
	case StageAuthenticateProvenance:
		parsed, err := document.Parse(doc)
		if err != nil {
			return malformed(stage)
		}
		codeRef, err := parsed.ReferenceValuesCollateral(document.CollateralSigstoreCodeV1Format)
		if err != nil {
			return reject(stage, "PROVENANCE_REJECTED")
		}
		code, err := prov.AuthenticateCode(codeRef.SigstoreBundle, in.Repo, codeRef.Tag, codeRef.Digest)
		if err != nil {
			return reject(stage, "PROVENANCE_REJECTED")
		}
		return Output{Stage: stage, Accepted: true, Outputs: &AcceptOutputs{
			CodeDigest:      code.Digest,
			CodeMeasurement: toMeasurement(code.Measurement),
		}}, ExitAccepted
	case StageAssemblePolicy:
		parsed, err := document.Parse(doc)
		if err != nil {
			return malformed(stage)
		}
		platRef, err := parsed.ReferenceValuesCollateral(document.CollateralSigstorePlatformV1Format)
		if err != nil {
			return reject(stage, "PROVENANCE_REJECTED")
		}
		if _, err := prov.AuthenticatePlatformEndorsements(platRef.SigstoreBundle, platRef.Repo, platRef.Tag, platRef.Digest); err != nil {
			return reject(stage, "PROVENANCE_REJECTED")
		}
		return Output{Stage: stage, Accepted: true}, ExitAccepted
	case StageAuthenticateQuote:
		parsed, err := document.Parse(doc)
		if err != nil {
			return malformed(stage)
		}
		auth, err := quote.Authenticate(parsed, quoteOpts)
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
func verifyFull(doc, nonce []byte, repo string, quoteOpts *quote.Options, core *verifier.Verifier) (Output, int) {
	parsed, reportData, err := document.Check(doc, nonce)
	if err != nil {
		return reject(StageVerify, "ENVELOPE_REJECTED")
	}
	code, endorsements, _, err := core.ReferenceValues(parsed, repo)
	if err != nil {
		return reject(StageVerify, "PROVENANCE_REJECTED")
	}
	auth, err := quote.Authenticate(parsed, quoteOpts)
	if err != nil {
		return reject(StageVerify, "QUOTE_REJECTED")
	}
	assembled, err := quote.Assemble(endorsements.Artifact, code.Measurement, nil, code.Shape, reportData, auth)
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
// the verified crypto material (hash-bound into the quote via document.Check).
func boundKeys(doc *document.Document) (tlsFP, hpke string) {
	for _, it := range doc.CryptoMaterialItems() {
		switch {
		case it.ID == document.CryptoMaterialIDTLS && it.Format == document.KeySPKIFPSHA256V1Format:
			tlsFP = it.Data
		case it.ID == document.CryptoMaterialIDHPKE && it.Format == document.KeyX25519HPKEV1Format:
			hpke = it.Data
		}
	}
	return
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

// newProvClient returns a provenance.Client that authenticates provenance
// against an injected Sigstore root, or the embedded root when none was
// supplied. The block stages drive provenance one layer at a time, so they
// hold a provenance client rather than a whole verifier.
func newProvClient(sigstoreRootJSON []byte) (*provenance.Client, error) {
	if sigstoreRootJSON == nil {
		return provenance.NewDefaultClient()
	}
	client, err := provenance.NewClientFromJSON(sigstoreRootJSON)
	if err != nil {
		return nil, fmt.Errorf("sigstore_trusted_root_json_b64: %w", err)
	}
	return client, nil
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

func malformed(stage string) (Output, int) {
	return Output{Stage: stage, Accepted: false, Rejection: &Rejection{Code: "MALFORMED_INPUT"}}, ExitMalformed
}
