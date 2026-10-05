package endorsement_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/tinfoil-config/endorsement"
)

const (
	specMaxSlugLength     = 63
	specMaxRevisionLength = 128
)

func TestTimestampCoreCanonicalization(t *testing.T) {
	s := &endorsement.Statement{
		Type:          endorsement.StatementType,
		Subject:       []endorsement.Subject{{Name: testName, Digest: map[string]string{"sha256": strings.Repeat("a", sha256.Size*2)}}},
		PredicateType: endorsement.PredicateType,
		Predicate:     endorsement.Predicate{AuditScope: testScope},
	}
	const core = `{"_type":"https://in-toto.io/Statement/v1","predicate":{"auditScope":"16a44d18-3387-44ce-9bfb-d77c4d27dbba"},"predicateType":"https://tinfoil.sh/predicate/config-endorsement/v1","subject":[{"digest":{"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"name":"/tinfoil/model-router/v0.0.155"}]}`
	want := append([]byte("tinfoil-config-freshness/v1\x00"), []byte(core)...)
	got, err := s.TimestampInput()
	require.NoError(t, err)
	require.Equal(t, want, got)
	imprint, err := s.TimestampImprint()
	require.NoError(t, err)
	require.Equal(t, sha256.Sum256(want), imprint)
	s.Predicate.Freshness = &endorsement.Freshness{RFC3161Timestamp: []byte("excluded from core")}
	withFreshness, err := s.TimestampInput()
	require.NoError(t, err)
	require.Equal(t, got, withFreshness)
}

func TestNamesAndAuditScopesAreCanonical(t *testing.T) {
	for _, invalid := range []string{
		"/org/project",
		"org/project/v1",
		"//org/project/v1",
		"/org//v1",
		"/org/Project/v1",
		"/Org/project/v1",
		"/org/project/enclave/v1",
		"/tinfoil/org/project/enclave/v1",
		"/org/../v1",
		"/org/project/../v1",
		"/org/project/%2F",
		"/org/project/v1/",
		"/org/project/.hidden",
		"/org/project/",
		"/org/project/v1\x00",
		"/org/project/" + strings.Repeat("a", specMaxRevisionLength+1),
		"/" + strings.Repeat("a", specMaxSlugLength+1) + "/project/v1",
		"/org/" + strings.Repeat("a", specMaxSlugLength+1) + "/v1",
	} {
		_, _, err := endorsement.ParseName(invalid)
		require.Error(t, err, invalid)
	}
	for _, valid := range []struct {
		name     string
		identity string
		revision string
	}{
		{testName, testIdentity, "v0.0.155"},
		{"/org/project/v0.1.0", "/org/project", "v0.1.0"},
		{"/org-1/project-2/Release_1.2-rc", "/org-1/project-2", "Release_1.2-rc"},
		{"/" + strings.Repeat("a", specMaxSlugLength) + "/" + strings.Repeat("b", specMaxSlugLength) + "/" + strings.Repeat("c", specMaxRevisionLength), "/" + strings.Repeat("a", specMaxSlugLength) + "/" + strings.Repeat("b", specMaxSlugLength), strings.Repeat("c", specMaxRevisionLength)},
	} {
		identity, revision, err := endorsement.ParseName(valid.name)
		require.NoError(t, err)
		require.Equal(t, valid.identity, identity)
		require.Equal(t, valid.revision, revision)
	}
	for _, invalid := range []string{"", "00000000-0000-0000-0000-000000000000", strings.ToUpper(testScope), strings.ReplaceAll(testScope, "-", "")} {
		require.Error(t, endorsement.ValidateAuditScope(invalid))
	}
}

func TestStrictStatementDecoding(t *testing.T) {
	f := newFixture(t)
	payload := f.statement(t, f.Now)
	for _, tc := range []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{"duplicate property", func(p []byte) []byte {
			return bytes.Replace(p, []byte(`"predicate":`), []byte(`"predicate":{},"predicate":`), 1)
		}},
		{"unknown property", func(p []byte) []byte {
			return bytes.Replace(p, []byte(`"predicate":{`), []byte(`"predicate":{"issuedAt":"2026-01-01",`), 1)
		}},
		{"case folding", func(p []byte) []byte { return bytes.Replace(p, []byte(`"auditScope":`), []byte(`"AuditScope":`), 1) }},
		{"trailing JSON", func(p []byte) []byte { return append(p, []byte(`{}`)...) }},
		{"invalid UTF-8", func(p []byte) []byte { return bytes.Replace(p, []byte(testName), []byte("/tinfoil/\xff"), 1) }},
		{"missing timestamp", func(p []byte) []byte {
			s, err := endorsement.ParseStatement(p)
			require.NoError(t, err)
			s.Predicate.Freshness = nil
			encoded, err := json.Marshal(s)
			require.NoError(t, err)
			return encoded
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := endorsement.ParseStatement(tc.mutate(bytes.Clone(payload)))
			require.Error(t, err)
		})
	}
	padded := append(bytes.Clone(payload), bytes.Repeat([]byte(" "), endorsement.MaxStatementSize-len(payload))...)
	_, err := endorsement.ParseStatement(padded)
	require.NoError(t, err)
	_, err = endorsement.ParseStatement(append(padded, ' '))
	require.ErrorContains(t, err, "statement size is outside allowed bounds")
}

func TestRenewalChangesApprovalWithoutChangingArtifact(t *testing.T) {
	f := newFixture(t)
	firstPayload := f.statement(t, f.Now.Add(-time.Minute))
	secondPayload := f.statement(t, f.Now)
	first, err := endorsement.ParseStatement(firstPayload)
	require.NoError(t, err)
	second, err := endorsement.ParseStatement(secondPayload)
	require.NoError(t, err)
	require.Equal(t, first.Subject, second.Subject)
	firstInput, err := first.TimestampInput()
	require.NoError(t, err)
	secondInput, err := second.TimestampInput()
	require.NoError(t, err)
	require.Equal(t, firstInput, secondInput)
	require.NotEqual(t, first.Predicate.Freshness.RFC3161Timestamp, second.Predicate.Freshness.RFC3161Timestamp)
	firstRef, err := endorsement.EndorsementReference(firstPayload)
	require.NoError(t, err)
	secondRef, err := endorsement.EndorsementReference(secondPayload)
	require.NoError(t, err)
	require.NotEqual(t, firstRef, secondRef)
	digest := sha256.Sum256(testConfig)
	require.Equal(t, hex.EncodeToString(digest[:]), first.Subject[0].Digest["sha256"])
	_, err = first.Complete(f.Timestamp(t, []byte("unrelated request"), f.Now))
	require.ErrorContains(t, err, "does not match")
}
