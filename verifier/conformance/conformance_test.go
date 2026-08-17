//go:build tinfoil_conformance

package conformance

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// fixture wraps the shared Input with the stage and expected outcome, for the
// go-native runner. The Input sub-object is exactly what the CLI reads on stdin.
type fixture struct {
	ID       string `json:"id"`
	Stage    string `json:"stage"`
	Input    Input  `json:"input"`
	Expected struct {
		Accepted           bool         `json:"accepted"`
		Code               string       `json:"code,omitempty"`
		TLSPublicKeyFP     string       `json:"tls_public_key_fp,omitempty"`
		HPKEPublicKey      string       `json:"hpke_public_key,omitempty"`
		CodeDigest         string       `json:"code_digest,omitempty"`
		CodeMeasurement    *Measurement `json:"code_measurement,omitempty"`
		EnclaveMeasurement *Measurement `json:"enclave_measurement,omitempty"`
	} `json:"expected"`
}

// TestFixtures runs every shared fixture in testdata/ through Run and asserts
// the expected accept/reject. Coverage grows as fixtures are added.
func TestFixtures(t *testing.T) {
	// The shared fixtures live in the conformance suite; point the harness at
	// them with TINFOIL_CONFORMANCE_FIXTURES, else fall back to local testdata.
	dir := os.Getenv("TINFOIL_CONFORMANCE_FIXTURES")
	if dir == "" {
		dir = "testdata"
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Skip("no fixtures in testdata/")
	}
	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			data, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			var f fixture
			if err := json.Unmarshal(data, &f); err != nil {
				t.Fatalf("loading fixture: %v", err)
			}
			out, _ := Run(f.Stage, f.Input)
			if out.Accepted != f.Expected.Accepted {
				t.Errorf("accepted=%v, want %v (rejection=%+v)", out.Accepted, f.Expected.Accepted, out.Rejection)
			}
			// When a reject fixture declares its spec-layer code, assert the
			// harness attributed the rejection to that layer.
			if !f.Expected.Accepted && f.Expected.Code != "" {
				got := ""
				if out.Rejection != nil {
					got = out.Rejection.Code
				}
				if got != f.Expected.Code {
					t.Errorf("rejection code=%q, want %q", got, f.Expected.Code)
				}
			}
			// When an accept fixture declares the verified facts, assert the
			// harness recovered exactly those. A client that accepts but yields a
			// different code digest, measurement register set, or channel key is
			// not conformant — this is what forces cross-SDK output equivalence.
			e := f.Expected
			if e.Accepted && (e.TLSPublicKeyFP != "" || e.CodeDigest != "" || e.CodeMeasurement != nil || e.EnclaveMeasurement != nil) {
				if out.Outputs == nil {
					t.Fatalf("accepted but no outputs; want declared facts")
				}
				o := out.Outputs
				if e.TLSPublicKeyFP != "" && o.TLSPublicKeyFP != e.TLSPublicKeyFP {
					t.Errorf("tls_public_key_fp=%q, want %q", o.TLSPublicKeyFP, e.TLSPublicKeyFP)
				}
				if e.HPKEPublicKey != "" && o.HPKEPublicKey != e.HPKEPublicKey {
					t.Errorf("hpke_public_key=%q, want %q", o.HPKEPublicKey, e.HPKEPublicKey)
				}
				if e.CodeDigest != "" && o.CodeDigest != e.CodeDigest {
					t.Errorf("code_digest=%q, want %q", o.CodeDigest, e.CodeDigest)
				}
				if e.CodeMeasurement != nil && !reflect.DeepEqual(o.CodeMeasurement, *e.CodeMeasurement) {
					t.Errorf("code_measurement=%+v, want %+v", o.CodeMeasurement, *e.CodeMeasurement)
				}
				if e.EnclaveMeasurement != nil && !reflect.DeepEqual(o.EnclaveMeasurement, *e.EnclaveMeasurement) {
					t.Errorf("enclave_measurement=%+v, want %+v", o.EnclaveMeasurement, *e.EnclaveMeasurement)
				}
			}
		})
	}
}
