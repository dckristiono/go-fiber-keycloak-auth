package keycloakauth

import (
	"github.com/stretchr/testify/assert"
	"io"
	"net/http"
	"strings"
	"testing"
)

// MockHTTPClient implements HTTPClient interface for testing
type MockHTTPClient struct {
	statusCode int
	response   string
}

func (m *MockHTTPClient) Get(url string) (*http.Response, error) {
	return &http.Response{
		StatusCode: m.statusCode,
		Body:       io.NopCloser(strings.NewReader(m.response)),
	}, nil
}

func (m *MockHTTPClient) SetResponse(statusCode int, response string) {
	m.statusCode = statusCode
	m.response = response
}

// TestNew tests the creation of a new KeycloakAuth instance
func TestNew(t *testing.T) {
	// Test with valid config
	config := Config{
		Realm:     "test-realm",
		ServerURL: "https://keycloak.example.com",
		ClientID:  "test-client",
	}

	auth := New(config)
	assert.NotNil(t, auth, "New should return a non-nil *KeycloakAuth")

	// Test with PublicKeyURL already set
	config = Config{
		Realm:        "test-realm",
		ServerURL:    "https://keycloak.example.com",
		ClientID:     "test-client",
		PublicKeyURL: "https://custom.example.com/keys",
	}

	auth = New(config)
	assert.NotNil(t, auth, "New should return a non-nil *KeycloakAuth")
}

// TestGetJWKS tests fetching the JWKS
func TestGetJWKS(t *testing.T) {
	// Create a mock HTTP client for testing
	mockClient := &MockHTTPClient{}

	// Setup the auth instance
	config := Config{
		Realm:     "test-realm",
		ServerURL: "https://keycloak.example.com",
		ClientID:  "test-client",
		CacheJWKS: true,
	}

	auth := New(config)
	auth.SetHTTPClient(mockClient)

	// Test successful JWKS fetch
	mockClient.SetResponse(http.StatusOK, mockJWKS)

	jwks, err := auth.getJWKS()
	assert.NoError(t, err)
	assert.NotNil(t, jwks)
	assert.Equal(t, 1, len(jwks.Keys))
	assert.Equal(t, "test-kid", jwks.Keys[0].Kid)

	// Test caching
	// Modify mock to return failure, but we should still get the cached result
	mockClient.SetResponse(http.StatusInternalServerError, "")

	jwks, err = auth.getJWKS()
	assert.NoError(t, err)
	assert.NotNil(t, jwks)

	// Test error handling
	// Create a new auth instance to bypass cache
	auth = New(config)
	auth.SetHTTPClient(mockClient)

	_, err = auth.getJWKS()
	assert.Error(t, err)

	// Test invalid JSON
	mockClient.SetResponse(http.StatusOK, "invalid json")

	auth = New(config)
	auth.SetHTTPClient(mockClient)

	_, err = auth.getJWKS()
	assert.Error(t, err)
}

// TestExtractTokenFromHeader tests token extraction from headers
func TestExtractTokenFromHeader(t *testing.T) {
	// Create a mock context
	ctx := &mockContext{
		headers: map[string]string{
			"Authorization": "Bearer test-token",
		},
	}

	// Test valid header
	token, err := extractTokenFromHeader(ctx)
	assert.NoError(t, err)
	assert.Equal(t, "test-token", token)

	// Test missing header
	ctx.headers = map[string]string{}
	_, err = extractTokenFromHeader(ctx)
	assert.Error(t, err)

	// Test invalid format
	ctx.headers = map[string]string{
		"Authorization": "NotBearer test-token",
	}
	_, err = extractTokenFromHeader(ctx)
	assert.Error(t, err)

	// Test no space
	ctx.headers = map[string]string{
		"Authorization": "Bearertest-token",
	}
	_, err = extractTokenFromHeader(ctx)
	assert.Error(t, err)
}

// Mock context for testing
type mockContext struct {
	headers map[string]string
}

func (m *mockContext) Get(key string) string {
	return m.headers[key]
}

// JWKS mock for testing
const mockJWKS = `{
  "keys": [
    {
      "kid": "test-kid",
      "kty": "RSA",
      "alg": "RS256",
      "use": "sig",
      "n": "test-n",
      "e": "AQAB",
      "x5c": ["test-x5c"]
    }
  ]
}`
