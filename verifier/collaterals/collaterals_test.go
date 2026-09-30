package collaterals

import (
	"strings"
	"testing"

	"github.com/tinfoilsh/tinfoil-go/verifier/document"
)

func TestRequestSourceSelection(t *testing.T) {
	ref := document.ConfigReference{Name: "/org/project/v1", Digest: strings.Repeat("a", 64)}
	for _, test := range []struct {
		name   string
		repo   string
		tag    string
		config *document.ConfigReference
		valid  bool
	}{
		{"repository", "org/repo", "v1", nil, true},
		{"config", "", "", &ref, true},
		{"missing source", "", "", nil, false},
		{"both sources", "org/repo", "", &ref, false},
		{"config with repository tag", "", "v1", &ref, false},
		{"noncanonical identity", "", "", &document.ConfigReference{Name: "/Org/project/v1", Digest: ref.Digest}, false},
		{"missing revision", "", "", &document.ConfigReference{Name: "/org/project", Digest: ref.Digest}, false},
		{"legacy identity", "", "", &document.ConfigReference{Name: "/tinfoil/org/project/enclave/v1", Digest: ref.Digest}, false},
		{"extra component", "", "", &document.ConfigReference{Name: "/org/project/enclave/v1", Digest: ref.Digest}, false},
		{"trailing slash", "", "", &document.ConfigReference{Name: "/org/project/v1/", Digest: ref.Digest}, false},
		{"encoded separator", "", "", &document.ConfigReference{Name: "/org/project/v1%2F", Digest: ref.Digest}, false},
		{"invalid digest", "", "", &document.ConfigReference{Name: ref.Name, Digest: strings.ToUpper(ref.Digest)}, false},
		{"oversized organization", "", "", &document.ConfigReference{Name: "/" + strings.Repeat("a", maxConfigSlugLength+1) + "/project/v1", Digest: ref.Digest}, false},
		{"oversized project", "", "", &document.ConfigReference{Name: "/org/" + strings.Repeat("a", maxConfigSlugLength+1) + "/v1", Digest: ref.Digest}, false},
		{"oversized revision", "", "", &document.ConfigReference{Name: "/org/project/" + strings.Repeat("a", maxConfigRevisionLength+1), Digest: ref.Digest}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := Request{Repo: test.repo, Tag: test.tag, Config: test.config, Platform: "sev-snp", QuoteBase64: "cXVvdGU="}
			if err := r.Validate(); (err == nil) != test.valid {
				t.Fatalf("Validate() = %v, valid = %v", err, test.valid)
			}
		})
	}
}
