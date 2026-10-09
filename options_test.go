package tinfoil

import (
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/openai/openai-go/v3/option"
	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/enclave"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

func TestLocalConfigRequiresAnExplicitEnclave(t *testing.T) {
	config := []byte("cvm-version: 0.15.0@sha256:" + strings.Repeat("ab", sha256.Size) + "\n")
	opts := WithVerificationOptions(enclave.Options{EmbeddedConfig: &verify.EmbeddedConfig{Bytes: config}})
	_, err := NewClientWithOptions(opts)
	require.ErrorContains(t, err, "embedded config requires an enclave")
	_, err = NewGateway("https://gateway.example", nil, GatewayOptions{ClientOptions: []ClientOption{opts}})
	require.ErrorContains(t, err, "embedded config requires a direct enclave client")
}

func TestClientOptionsDefaults(t *testing.T) {
	cfg := &clientConfig{
		repo:      defaultConfigRepo,
		transport: defaultTransportMode,
	}
	require.Equal(t, TransportEHBP, cfg.transport)
	require.Equal(t, "tinfoilsh/confidential-model-router", cfg.repo)
}

func TestClientOptionsApply(t *testing.T) {
	cfg := &clientConfig{}
	for _, opt := range []ClientOption{
		WithEnclave("enclave.example.com"),
		WithRepo("org/repo"),
		WithTransport(TransportTLS),
		WithOpenAIOptions(option.WithAPIKey("k1"), option.WithAPIKey("k2")),
	} {
		opt(cfg)
	}

	require.Equal(t, "enclave.example.com", cfg.enclave)
	require.Equal(t, "org/repo", cfg.repo)
	require.Equal(t, TransportTLS, cfg.transport)
	require.Len(t, cfg.openaiOpts, 2)
}

func TestProxyClientOptionsApply(t *testing.T) {
	cfg := &clientConfig{}
	WithBaseURL("https://proxy.example.com/")(cfg)

	require.Equal(t, "https://proxy.example.com/", cfg.baseURL)
	require.True(t, cfg.baseURLSet)
}

func TestNewClientWithOptionsRejectsInvalidBaseURL(t *testing.T) {
	for _, baseURL := range []string{"", "proxy.example.com", "ftp://proxy.example.com", "://", "http://proxy.example.com/v1"} {
		t.Run(baseURL, func(t *testing.T) {
			_, err := NewClientWithOptions(WithBaseURL(baseURL))
			var config *ConfigurationError
			require.ErrorAs(t, err, &config)
			require.Contains(t, err.Error(), "invalid base URL")
		})
	}
}

func TestNewClientWithOptionsRequiresEnclaveForCustomRepo(t *testing.T) {
	for _, opt := range []ClientOption{
		WithRepo("org/repo"),
		WithRepo(defaultConfigRepo + "@v1"),
		WithRepo(defaultConfigRepo + "@sha256:" + strings.Repeat("ab", 32)),
	} {
		c, err := NewClientWithOptions(opt)
		require.Nil(t, c)
		require.ErrorContains(t, err, "requires an enclave")
	}
}
