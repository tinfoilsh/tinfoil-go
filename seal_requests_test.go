package tinfoil

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	ehbpidentity "github.com/tinfoilsh/encrypted-http-body-protocol/identity"
)

func sealMultipart(t *testing.T, models []string, modelFirst bool) ([]byte, string) {
	t.Helper()
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	require.NoError(t, w.SetBoundary("test-upload-boundary"))
	writeModels := func() {
		for _, model := range models {
			require.NoError(t, w.WriteField("model", model))
		}
	}
	if modelFirst {
		writeModels()
	}
	file, err := w.CreateFormFile("file", "audio.wav")
	require.NoError(t, err)
	_, err = file.Write([]byte("RIFF\x00\xff\r\nprivate audio bytes\r\n"))
	require.NoError(t, err)
	if !modelFirst {
		writeModels()
	}
	require.NoError(t, w.WriteField("language", "en"))
	require.NoError(t, w.Close())
	return body.Bytes(), `multipart/form-data; boundary="test-upload-boundary"`
}

func TestSealMultipartRoutingAndReplay(t *testing.T) {
	for _, modelFirst := range []bool{false, true} {
		for _, recovery := range []string{"reroute", "key rotation"} {
			t.Run(recovery+map[bool]string{false: "/model after file", true: "/model before file"}[modelFirst], func(t *testing.T) {
				body, contentType := sealMultipart(t, []string{sealTestModel}, modelFirst)
				var attempts int
				seal := sealTestTransport(func(host string) (http.RoundTripper, error) {
					return &recoveryTransport{transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
						attempts++
						defer req.Body.Close()
						got, err := io.ReadAll(req.Body)
						require.NoError(t, err)
						require.Equal(t, body, got, "multipart bytes must survive every attempt")
						require.Equal(t, contentType, req.Header.Get("Content-Type"))
						require.Equal(t, sealTestModel, req.Header.Get(modelHeader))
						require.Equal(t, host, req.Header.Get(sealHeader))
						require.Equal(t, int64(len(body)), req.ContentLength)
						if attempts == 1 {
							if recovery == "reroute" {
								return sealMismatch("next.example"), nil
							}
							return nil, testKeyRejection{errors.New("rotated key")}
						}
						return newResponse(http.StatusOK, `{"text":"transcribed"}`), nil
					})}, nil
				})
				req := httptest.NewRequest(http.MethodPost, "https://gateway.example/v1/audio/transcriptions", bytes.NewReader(body))
				req.ContentLength = -1
				req.Header.Set("Content-Type", contentType)
				require.Nil(t, req.GetBody)
				resp, err := seal.RoundTrip(req)
				require.NoError(t, err)
				resp.Body.Close()
				require.Equal(t, 2, attempts)
				require.Empty(t, req.Header.Get(modelHeader), "do not mutate caller headers")
			})
		}
	}
}

func TestSealMultipartRejectsInvalidFormsBeforeVerification(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		models     []string
	}{
		{"missing", "missing its model", nil},
		{"empty", "must not be empty", []string{""}},
		{"blank", "must not be empty", []string{" \t"}},
		{"duplicate", "exactly one model", []string{sealTestModel, sealTestModel}},
		{"conflicting", "exactly one model", []string{sealTestModel, "another-model"}},
		{"truncated", "multipart", []string{sealTestModel}},
		{"missing boundary", "missing its boundary", []string{sealTestModel}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, contentType := sealMultipart(t, tc.models, false)
			if tc.name == "truncated" {
				body = body[:len(body)-12]
			}
			if tc.name == "missing boundary" {
				contentType = "multipart/form-data"
			}
			original := &sealTestBody{Reader: bytes.NewReader(body)}
			req := httptest.NewRequest(http.MethodPost, "https://gateway.example/v1/audio/transcriptions", original)
			req.Header.Set("Content-Type", contentType)
			seal := sealTestTransport(func(string) (http.RoundTripper, error) {
				t.Fatal("invalid forms must not start attestation or inference")
				return nil, nil
			})
			_, err := seal.RoundTrip(req)
			var config *ConfigurationError
			require.ErrorAs(t, err, &config)
			require.ErrorContains(t, err, tc.want)
			require.Equal(t, 1, original.closes)
		})
	}
}

type sealUploadReader struct {
	remaining int64
	err       error
}

func (r *sealUploadReader) Read(p []byte) (int, error) {
	if r.err != nil {
		return 0, r.err
	}
	if r.remaining == 0 {
		return 0, io.EOF
	}
	n := min(int64(len(p)), r.remaining)
	clear(p[:n])
	r.remaining -= n
	return int(n), nil
}

func TestSealMultipartReadLimitsAndFailures(t *testing.T) {
	readErr := errors.New("upload interrupted")
	for _, tc := range []struct {
		name   string
		reader io.Reader
	}{
		{"oversized", &sealUploadReader{remaining: maxMultipartBodySize + 1}},
		{"read failure", &sealUploadReader{err: readErr}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := &sealTestBody{Reader: tc.reader}
			req := httptest.NewRequest(http.MethodPost, "https://gateway.example/v1/audio/transcriptions", original)
			req.Header.Set("Content-Type", "multipart/form-data; boundary=test")
			seal := sealTestTransport(func(string) (http.RoundTripper, error) {
				t.Fatal("unreadable uploads must not reach verification")
				return nil, nil
			})
			_, err := seal.RoundTrip(req)
			if tc.name == "oversized" {
				var tooLarge *http.MaxBytesError
				require.ErrorAs(t, err, &tooLarge)
				require.Equal(t, int64(maxMultipartBodySize), tooLarge.Limit)
			} else {
				require.ErrorIs(t, err, readErr)
			}
			require.Equal(t, 1, original.closes)
		})
	}
}

func TestSealCacheScopesAPIKeysAndUsers(t *testing.T) {
	const head = `{"role":"user","content":"hello"}`
	scope := func(authorization, secret, override, messages string) (string, string) {
		t.Helper()
		body := `{"model":"test-model","messages":` + messages
		if override != "" {
			body += `,"user_cache_secret":"` + override + `"`
		}
		body += `}`
		req := httptest.NewRequest(http.MethodPost, "https://gateway.example/v1/chat/completions", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", authorization)
		req.Header.Set(cachePrefixHeader, "caller-supplied-prefix")
		seal := &sealTransport{secret: secret}
		require.NoError(t, seal.prepare(req))
		defer req.Body.Close()
		var fields map[string]any
		require.NoError(t, json.NewDecoder(req.Body).Decode(&fields))
		require.NotContains(t, fields, userCacheSecretField)
		require.Equal(t, authorization, req.Header.Get("Authorization"))
		return fields[cacheSaltField].(string), req.Header.Get(cachePrefixHeader)
	}
	first := "[" + head + "]"
	salt, prefix := scope("Bearer test-api-key", "test-secret", "", first)
	// RFC 5869 vectors computed with Python's hashlib/hmac.
	require.Equal(t, "DpKycpNLBpMrAyjpNCVBx66rSpZVwsZJPz5Ty66bBy8", salt)
	require.Equal(t, "ede1ce81b1779c5d9431ab8d3a073b06a8507da5cc3178ff385c13cef8ff02f6", prefix)
	for _, tc := range []struct{ auth, secret string }{
		{"Bearer another-api-key", "test-secret"},
		{"Bearer test-api-key", "another-secret"},
		{"", "test-secret"},
	} {
		otherSalt, otherPrefix := scope(tc.auth, tc.secret, "", first)
		require.NotEqual(t, salt, otherSalt)
		require.NotEqual(t, prefix, otherPrefix)
	}
	for _, auth := range []string{"Bearer test-api-key", "bEaReR  test-api-key "} {
		gotSalt, gotPrefix := scope(auth, "other-default", "test-secret", first)
		require.Equal(t, salt, gotSalt, "per-request secret wins")
		require.Equal(t, prefix, gotPrefix)
	}
	gotSalt, gotPrefix := scope("Bearer test-api-key", "test-secret", "", "["+head+`,{"role":"user","content":"next turn"}]`)
	require.Equal(t, salt, gotSalt)
	require.Equal(t, prefix, gotPrefix, "later turns retain affinity")
	gotSalt, gotPrefix = scope("Bearer test-api-key", "test-secret", "", `[{"role":"user","content":"different"}]`)
	require.Equal(t, salt, gotSalt)
	require.NotEqual(t, prefix, gotPrefix, "different conversations have different routing values")
	_, gotPrefix = scope("Bearer test-api-key", "test-secret", "", `[]`)
	require.Empty(t, gotPrefix, "do not leak caller-provided routing values")
}

func TestSealMultipartAndCacheBodiesAreEncrypted(t *testing.T) {
	upload, multipartType := sealMultipart(t, []string{sealTestModel}, false)
	for _, tc := range []struct {
		name, path, contentType string
		body                    []byte
	}{
		{"audio", "/v1/audio/transcriptions", multipartType, upload},
		{"cache scoping", "/v1/chat/completions", "application/json", []byte(`{"model":"test-model","messages":[{"role":"user","content":"hello"}],"user_cache_secret":"test-secret"}`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			identity, err := ehbpidentity.NewIdentity()
			require.NoError(t, err)
			type received struct {
				body   []byte
				header http.Header
				err    error
			}
			wire, plain := make(chan received, 1), make(chan received, 1)
			decrypt := identity.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				plain <- received{body, r.Header.Clone(), err}
				w.Header().Set("Content-Type", "application/json")
				io.WriteString(w, `{}`)
			}))
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				r.Body.Close()
				wire <- received{body, r.Header.Clone(), err}
				r.Body = io.NopCloser(bytes.NewReader(body))
				decrypt.ServeHTTP(w, r)
			}))
			defer server.Close()
			seal := sealTestTransport(func(string) (http.RoundTripper, error) {
				// Attestation is stubbed with this test key.
				return buildEHBPTransport(identity.MarshalPublicKeyHex())
			})
			req := httptest.NewRequest(http.MethodPost, server.URL+tc.path, bytes.NewReader(tc.body))
			req.RequestURI = ""
			req.Header.Set("Content-Type", tc.contentType)
			req.Header.Set("Authorization", "Bearer test-api-key")
			resp, err := seal.RoundTrip(req)
			require.NoError(t, err)
			defer resp.Body.Close()
			require.Equal(t, http.StatusOK, resp.StatusCode)
			_, err = io.ReadAll(resp.Body)
			require.NoError(t, err)
			outer, inner := <-wire, <-plain
			require.NoError(t, outer.err)
			require.NoError(t, inner.err)
			require.NotContains(t, string(outer.body), "private audio bytes")
			require.NotContains(t, string(outer.body), "test-secret")
			require.NotContains(t, string(outer.body), "hello")
			require.Equal(t, sealTestModel, outer.header.Get(modelHeader))
			if tc.name == "audio" {
				require.Equal(t, upload, inner.body)
				require.Equal(t, multipartType, inner.header.Get("Content-Type"))
			} else {
				const salt = "DpKycpNLBpMrAyjpNCVBx66rSpZVwsZJPz5Ty66bBy8"
				require.NotContains(t, string(outer.body), salt)
				require.NotContains(t, outer.header, "cache_salt")
				require.Equal(t, "ede1ce81b1779c5d9431ab8d3a073b06a8507da5cc3178ff385c13cef8ff02f6", outer.header.Get(cachePrefixHeader))
				var fields map[string]any
				require.NoError(t, json.Unmarshal(inner.body, &fields))
				require.Equal(t, salt, fields[cacheSaltField])
				require.NotContains(t, fields, userCacheSecretField)
			}
		})
	}
}
