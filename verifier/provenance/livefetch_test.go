package provenance

// Test-only helpers for the live canary tests: they fetch published release
// artifacts through the Tinfoil GitHub proxy. Production verification never
// fetches reference values — they travel inside the attestation document.

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/tinfoilsh/tinfoil-go/verifier/util"
)

const githubProxy = "https://github-proxy.tinfoil.sh"

func fetchLatestDigest(repo string) (string, error) {
	releaseResponse, _, err := util.Get(githubProxy + "/repos/" + repo + "/releases/latest")
	if err != nil {
		return "", err
	}
	var release struct {
		TagName string `json:"tag_name"`
	}
	if err := json.Unmarshal(releaseResponse, &release); err != nil {
		return "", err
	}

	digest, _, err := util.Get(fmt.Sprintf("%s/%s/releases/download/%s/tinfoil.hash", githubProxy, repo, release.TagName))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(digest)), nil
}

func fetchAttestationBundle(repo, digest string) ([]byte, error) {
	bundleResponse, _, err := util.Get(githubProxy + "/repos/" + repo + "/attestations/sha256:" + digest)
	if err != nil {
		return nil, err
	}
	var response struct {
		Attestations []struct {
			Bundle json.RawMessage `json:"bundle"`
		} `json:"attestations"`
	}
	if err := json.Unmarshal(bundleResponse, &response); err != nil {
		return nil, err
	}
	if len(response.Attestations) == 0 {
		return nil, fmt.Errorf("no attestations found for digest %s", digest)
	}
	return response.Attestations[0].Bundle, nil
}
