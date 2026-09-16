package github

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type releaseTransportFunc func(*http.Request) (*http.Response, error)

func (f releaseTransportFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestFetchLatestReleaseSelection(t *testing.T) {
	digest := strings.Repeat("a", 64)
	for _, tc := range []struct {
		name, repo, tag, digest string
		paths                   []string
	}{
		{name: "latest", repo: "owner/repo", tag: "v1.2.3", digest: digest, paths: []string{
			"/repos/owner/repo/releases/latest", "/owner/repo/releases/download/v1.2.3/tinfoil.hash",
		}},
		{name: "pinned", repo: "owner/repo@sha256:" + digest, digest: digest},
		{name: "empty pin never selects latest", repo: "owner/repo@sha256:"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var paths []string
			previous := http.DefaultClient.Transport
			t.Cleanup(func() { http.DefaultClient.Transport = previous })
			http.DefaultClient.Transport = releaseTransportFunc(func(r *http.Request) (*http.Response, error) {
				paths = append(paths, r.URL.Path)
				body := digest + "\n"
				if strings.HasSuffix(r.URL.Path, "/releases/latest") {
					body = `{"tag_name":"v1.2.3"}`
				}
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body))}, nil
			})

			release, err := FetchLatestRelease(tc.repo)
			require.NoError(t, err)
			assert.Equal(t, &Release{Tag: tc.tag, Digest: tc.digest}, release)
			assert.Equal(t, tc.paths, paths)
		})
	}
}

func TestGitHubFetchDigest(t *testing.T) {
	repo := "tinfoilsh/confidential-llama3-3-70b"
	tag := "v0.0.1"

	digest, err := FetchDigest(repo, tag)
	assert.NoError(t, err, "Failed to fetch digest for %s@%s", repo, tag)
	assert.NotEmpty(t, digest)

	latestDigest, err := FetchLatestDigest(repo)
	assert.NoError(t, err, "Failed to fetch latest digest for %s", repo)
	assert.NotEmpty(t, latestDigest, "Expected non-empty latest digest")
}

func TestFetchAttestationBundle(t *testing.T) {
	repo := "tinfoilsh/confidential-llama3-3-70b"
	tag := "v0.0.1"

	digest, err := FetchDigest(repo, tag)
	assert.NoError(t, err)

	bundle, err := FetchAttestationBundle(repo, digest)
	assert.NoError(t, err, "Failed to fetch attestation bundle for %s with digest %s", repo, digest)
	assert.NotEmpty(t, bundle)
}
