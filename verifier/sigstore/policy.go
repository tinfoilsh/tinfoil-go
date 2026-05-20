package sigstore

// Policy carries the Tinfoil Sigstore policy fields. Each field maps to a
// SPEC §5 clause. DefaultPolicy returns the canonical Tinfoil settings used
// by the standard verification path; the conformance binary builds alternative
// policies to exercise specific clauses.
//
// Mirrors the SigstorePolicy structs in tinfoil-rs, tinfoil-js, and
// tinfoil-python so the cross-SDK conformance suite can pass identical
// policy objects to every SDK.
type Policy struct {
	// OIDCIssuer: expected OIDC issuer extension value (exact match). SPEC §5.3.
	OIDCIssuer string
	// WorkflowRefPrefix: required prefix on the cert's GitHubWorkflowRef
	// extension value (e.g. "refs/tags/"). SPEC §5.3.
	WorkflowRefPrefix string
	// WorkflowRepository: expected GitHubWorkflowRepository extension value
	// (exact match). SPEC §5.3.
	WorkflowRepository string
	// PredicateTypesAllowed: allow-list of predicate type URIs (SPEC §5.5).
	// nil means any.
	PredicateTypesAllowed []string
	// InTotoStatementTypesAllowed: allow-list of in-toto statement `_type`
	// values. nil means any. SPEC §5.4 is silent here; Tinfoil's default
	// pins to v0.1/v1.
	InTotoStatementTypesAllowed []string
	// PayloadType: required DSSE envelope `payload_type` (exact match). SPEC §5.4.
	PayloadType string
}

// DefaultPolicy returns the canonical Tinfoil policy: GitHub Actions OIDC,
// tag-triggered builds, multiplatform predicate, in-toto v0.1/v1 statements.
func DefaultPolicy(repo string) Policy {
	return Policy{
		OIDCIssuer:         "https://token.actions.githubusercontent.com",
		WorkflowRefPrefix:  "refs/tags/",
		WorkflowRepository: repo,
		PredicateTypesAllowed: []string{
			"https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1",
		},
		InTotoStatementTypesAllowed: []string{
			"https://in-toto.io/Statement/v0.1",
			"https://in-toto.io/Statement/v1",
		},
		PayloadType: "application/vnd.in-toto+json",
	}
}

// Verification carries the extracted measurement plus the bundle/cert
// observables surfaced to the cross-SDK conformance harness.
type Verification struct {
	Measurement             *MeasurementOutput
	PredicateType           string
	InTotoStatementType     string
	SubjectName             string
	SubjectDigestSHA256Hex  string
	CertOIDCIssuer          string
	CertWorkflowRepository  string
	CertWorkflowSignerURI   string
	RekorLogIDHex           string
	RekorIntegratedTimeUnix int64
	TLogEntryCount          int
	SCTCount                int
}

// MeasurementOutput is a serializable view of the measurement extracted from
// a verified bundle. The `type` is the canonical predicate-type URI.
type MeasurementOutput struct {
	Type      string
	Registers []string
}
