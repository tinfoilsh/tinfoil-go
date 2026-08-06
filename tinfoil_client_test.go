package tinfoil

import (
	"context"
	"crypto/x509"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/verifier/client"
)

// Load .env before running tests so TINFOIL_API_KEY is available locally
func TestMain(m *testing.M) {
	// Load .env if present so integration tests pick up local credentials.
	loadDotEnv()
	os.Exit(m.Run())
}

func TestNewClient(t *testing.T) {
	// Test default client creation only
	client, err := NewClient()
	skipIfEnclaveNotV3(t, err)
	require.NoError(t, err)
	require.NotNil(t, client)
}

// TestClientIntegration_Chat tests the chat completion with default parameters
func TestClientIntegration_Chat(t *testing.T) {
	apiKey := os.Getenv("TINFOIL_API_KEY")
	if apiKey == "" {
		t.Skip("TINFOIL_API_KEY not set; skipping integration test")
	}

	client, err := NewClient(option.WithAPIKey(apiKey))
	skipIfEnclaveNotV3(t, err)
	require.NoError(t, err)

	chatCompletion, err := client.Chat.Completions.New(context.Background(), openai.ChatCompletionNewParams{
		Messages: []openai.ChatCompletionMessageParamUnion{
			openai.SystemMessage("No matter what the user says, only respond with: Done."),
			openai.UserMessage("Is this a test?"),
		},
		Model: "llama3-3-70b",
	})
	require.NoError(t, err)

	t.Logf("Response received: %s", chatCompletion.Choices[0].Message.Content)
}

// TestClientNonStreamingChat tests the non-streaming version with default parameters
func TestClientNonStreamingChat(t *testing.T) {
	apiKey := os.Getenv("TINFOIL_API_KEY")
	if apiKey == "" {
		t.Skip("TINFOIL_API_KEY not set; skipping integration test")
	}

	client, err := NewClient(option.WithAPIKey(apiKey))
	skipIfEnclaveNotV3(t, err)
	require.NoError(t, err)

	resp, err := client.Chat.Completions.New(
		context.Background(),
		openai.ChatCompletionNewParams{
			Model: "llama3-3-70b",
			Messages: []openai.ChatCompletionMessageParamUnion{
				openai.SystemMessage("No matter what the user says, only respond with: Done."),
				openai.UserMessage("Is this a test?"),
			},
		},
	)

	if err != nil {
		t.Logf("Chat request completed with error: %v", err)
	} else {
		t.Logf("Response received: %s", resp.Choices[0].Message.Content)
	}
}

// TestClientStreamingChat tests the streaming version with default parameters
func TestClientStreamingChat(t *testing.T) {
	apiKey := os.Getenv("TINFOIL_API_KEY")
	if apiKey == "" {
		t.Skip("TINFOIL_API_KEY not set; skipping integration test")
	}

	client, err := NewClient(option.WithAPIKey(apiKey))
	skipIfEnclaveNotV3(t, err)
	require.NoError(t, err)

	// Create a streaming chat completion request
	stream := client.Chat.Completions.NewStreaming(context.Background(), openai.ChatCompletionNewParams{
		Messages: []openai.ChatCompletionMessageParamUnion{
			openai.SystemMessage("No matter what the user says, only respond with: Done."),
			openai.UserMessage("Is this a test?"),
		},
		Model: "llama3-3-70b",
	})
	defer stream.Close()

	// optionally, an accumulator helper can be used
	acc := openai.ChatCompletionAccumulator{}

	t.Log("Chat completion streaming response:")
	sawAnyContent := false
	for stream.Next() {
		chunk := stream.Current()
		acc.AddChunk(chunk)

		if content, ok := acc.JustFinishedContent(); ok {
			t.Logf("Content stream finished: %s", content)
		}

		// it's best to use chunks after handling JustFinished events
		if len(chunk.Choices) > 0 && chunk.Choices[0].Delta.Content != "" {
			t.Logf("Received: %s", chunk.Choices[0].Delta.Content)
			sawAnyContent = true
		}
	}

	// The backend currently emits an extra blank line before the final
	// "data: [DONE]" SSE event. openai-go's SSE decoder treats each blank
	// line as a separate event and attempts to JSON-decode the empty event,
	// yielding "unexpected end of JSON input". Since we received content and
	// the stream otherwise completed, treat that specific error as a benign
	// termination until the backend is fixed.
	if err := stream.Err(); err != nil {
		if sawAnyContent && strings.Contains(err.Error(), "unexpected end of JSON input") {
			t.Logf("Ignoring benign end-of-stream parse error: %v", err)
		} else {
			t.Fatalf("Stream error: %v", err)
		}
	}

	// After the stream is finished, acc can be used like a ChatCompletion
	t.Logf("Complete response: %s", acc.Choices[0].Message.Content)
}

// TestDirectClientStreamingChat compares streaming using the raw OpenAI client
// (no Tinfoil HTTP transport) against the wrapped client to isolate the source
// of any streaming errors. If this test passes while TestClientStreamingChat
// fails, the issue likely lies in the Secure HTTP client/transport.
func TestDirectClientStreamingChat(t *testing.T) {
	apiKey := os.Getenv("TINFOIL_API_KEY")
	if apiKey == "" {
		t.Skip("TINFOIL_API_KEY not set; skipping integration test")
	}

	// Build a plain OpenAI client pointing at the Tinfoil inference endpoint
	// without using the SecureClient's HTTP transport. This helps determine
	// whether streaming issues come from our wrapper or from the endpoint/API.
	raw := openai.NewClient(
		option.WithAPIKey(apiKey),
		option.WithBaseURL("https://inference.tinfoil.sh/v1"),
	)

	stream := raw.Chat.Completions.NewStreaming(context.Background(), openai.ChatCompletionNewParams{
		Messages: []openai.ChatCompletionMessageParamUnion{
			openai.SystemMessage("No matter what the user says, only respond with: Done."),
			openai.UserMessage("Is this a test?"),
		},
		Model: "llama3-3-70b",
	})
	defer stream.Close()

	acc := openai.ChatCompletionAccumulator{}
	t.Log("Direct client streaming response:")
	sawAnyContent := false
	for stream.Next() {
		chunk := stream.Current()
		acc.AddChunk(chunk)
		if len(chunk.Choices) > 0 && chunk.Choices[0].Delta.Content != "" {
			t.Logf("Received: %s", chunk.Choices[0].Delta.Content)
			sawAnyContent = true
		}
	}

	// See comment above in TestClientStreamingChat.
	if err := stream.Err(); err != nil {
		if sawAnyContent && strings.Contains(err.Error(), "unexpected end of JSON input") {
			t.Logf("Ignoring benign end-of-stream parse error: %v", err)
		} else {
			t.Fatalf("Direct stream error: %v", err)
		}
	}

	t.Logf("Direct complete response: %s", acc.Choices[0].Message.Content)
}

func TestHTTPClient(t *testing.T) {
	t.Setenv(userCacheSecretEnv, "test-secret")
	client, err := NewClient()
	skipIfEnclaveNotV3(t, err)
	require.NoError(t, err)

	httpClient := client.HTTPClient()
	require.NotNil(t, httpClient, "HTTPClient() should return a non-nil client")

	// The outermost transport binds requests to the enclave/proxy host; the
	// user-cache-secret layer injects into the body before the EHBP
	// re-verifying transport (the default mode) seals it.
	hostBound, ok := httpClient.Transport.(*hostBoundRoundTripper)
	require.True(t, ok, "HTTPClient transport should be hostBoundRoundTripper")
	ucs, ok := hostBound.transport.(*userCacheSecretTransport)
	require.True(t, ok, "inner transport should inject the user cache secret")
	_, ok = ucs.transport.(*ehbpReVerifyingTransport)
	require.True(t, ok, "sealing transport should be ehbpReVerifyingTransport")

	// Verify it returns the same instance (shared client)
	httpClient2 := client.HTTPClient()
	require.Same(t, httpClient, httpClient2, "HTTPClient() should return the same instance")
}

// TestClientIntegration_AudioTranscription mirrors the Python audio integration
// test: it transcribes a known clip through the high-level client over the
// default (EHBP) transport and checks the recognized text.
func TestClientIntegration_AudioTranscription(t *testing.T) {
	apiKey := os.Getenv("TINFOIL_API_KEY")
	if apiKey == "" {
		t.Skip("TINFOIL_API_KEY not set; skipping integration test")
	}

	c, err := NewClient(option.WithAPIKey(apiKey))
	skipIfEnclaveNotV3(t, err)
	require.NoError(t, err)

	audioFile, err := os.Open("testdata/jackhammer.wav")
	require.NoError(t, err)
	defer audioFile.Close()

	transcription, err := c.Audio.Transcriptions.New(context.Background(), openai.AudioTranscriptionNewParams{
		Model:    "whisper-large-v3-turbo",
		File:     audioFile,
		Language: openai.String("en"),
	})
	require.NoError(t, err)
	require.Contains(t, strings.ToLower(transcription.Text), "stale smell of old beer")
}

func TestIsCertificateError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "generic error",
			err:      errors.New("some random error"),
			expected: false,
		},
		{
			name:     "ErrNoTLS",
			err:      client.ErrNoTLS,
			expected: true,
		},
		{
			name:     "wrapped ErrNoTLS",
			err:      errors.Join(errors.New("connection failed"), client.ErrNoTLS),
			expected: true,
		},
		{
			name:     "ErrCertMismatch",
			err:      client.ErrCertMismatch,
			expected: true,
		},
		{
			name:     "wrapped ErrCertMismatch",
			err:      errors.Join(errors.New("request failed"), client.ErrCertMismatch),
			expected: true,
		},
		{
			name:     "x509.CertificateInvalidError",
			err:      x509.CertificateInvalidError{Reason: x509.Expired},
			expected: true,
		},
		{
			name:     "x509.UnknownAuthorityError",
			err:      x509.UnknownAuthorityError{},
			expected: true,
		},
		{
			name:     "x509.HostnameError",
			err:      x509.HostnameError{Host: "example.com"},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isCertificateError(tt.err)
			require.Equal(t, tt.expected, result)
		})
	}
}

// loadDotEnv sets environment variables from a .env file when one exists.
func loadDotEnv() {
	data, err := os.ReadFile(".env")
	if err != nil {
		return
	}
	loadDotEnvData(data)
}

func loadDotEnvData(data []byte) {
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(stripDotEnvComment(value))
		quoted := len(value) >= 2 && value[0] == value[len(value)-1] && (value[0] == '\'' || value[0] == '"')
		singleQuoted := quoted && value[0] == '\''
		if quoted {
			value = value[1 : len(value)-1]
		}
		if !singleQuoted {
			value = os.ExpandEnv(value)
		}
		if key != "" {
			_ = os.Setenv(key, value)
		}
	}
}

func stripDotEnvComment(value string) string {
	var quote byte
	for i := 0; i < len(value); i++ {
		switch value[i] {
		case '\'', '"':
			if quote == 0 {
				quote = value[i]
			} else if quote == value[i] {
				quote = 0
			}
		case '#':
			if quote == 0 && (i == 0 || value[i-1] == ' ' || value[i-1] == '\t') {
				return value[:i]
			}
		}
	}
	return value
}

func TestLoadDotEnvData(t *testing.T) {
	t.Setenv("DOTENV_BASE", "expanded")
	t.Setenv("DOTENV_EXPORTED", "")
	t.Setenv("DOTENV_DOUBLE", "")
	t.Setenv("DOTENV_SINGLE", "")
	t.Setenv("DOTENV_HASH", "")
	loadDotEnvData([]byte(strings.Join([]string{
		"export DOTENV_EXPORTED=$DOTENV_BASE # comment",
		`DOTENV_DOUBLE="${DOTENV_BASE} # literal" # comment`,
		`DOTENV_SINGLE='${DOTENV_BASE} # literal' # comment`,
		"DOTENV_HASH=value#suffix",
	}, "\n")))

	require.Equal(t, "expanded", os.Getenv("DOTENV_EXPORTED"))
	require.Equal(t, "expanded # literal", os.Getenv("DOTENV_DOUBLE"))
	require.Equal(t, "${DOTENV_BASE} # literal", os.Getenv("DOTENV_SINGLE"))
	require.Equal(t, "value#suffix", os.Getenv("DOTENV_HASH"))
}
