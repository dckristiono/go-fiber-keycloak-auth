package keycloakauth

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
)

// MockHTTPClientMiddleware implements HTTPClient interface for middleware testing
type MockHTTPClientMiddleware struct {
	statusCode int
	response   string
}

func (m *MockHTTPClientMiddleware) Get(url string) (*http.Response, error) {
	return &http.Response{
		StatusCode: m.statusCode,
		Body:       io.NopCloser(strings.NewReader(m.response)),
	}, nil
}

func (m *MockHTTPClientMiddleware) SetResponse(statusCode int, response string) {
	m.statusCode = statusCode
	m.response = response
}

// JWKS mock for middleware testing
const mockJWKSMiddleware = `{
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

// TestAuth tests the unified Auth middleware
func TestAuth(t *testing.T) {
	// Setup auth
	config := Config{
		Realm:     "test-realm",
		ServerURL: "https://keycloak.example.com",
		ClientID:  "test-client",
	}

	auth := New(config)

	// Create a mock HTTP client
	mockClient := &MockHTTPClientMiddleware{}
	mockClient.SetResponse(http.StatusOK, mockJWKSMiddleware)
	auth.SetHTTPClient(mockClient)

	// Test required authentication with no token
	app := setupTestApp(auth.Auth(AuthOptions{
		Required: true,
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	resp, err := app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)

	// Test optional authentication with no token
	app = setupTestApp(auth.Auth(AuthOptions{
		Required: false,
	}))

	req = httptest.NewRequest("GET", "/test", nil)
	resp, err = app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	// Test with invalid token format
	app = setupTestApp(auth.Auth(AuthOptions{
		Required: true,
	}))

	req = httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "InvalidFormat")
	resp, err = app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
}

// TestAuthWithRoles tests the Auth middleware with roles
func TestAuthWithRoles(t *testing.T) {
	// Setup auth
	config := Config{
		Realm:     "test-realm",
		ServerURL: "https://keycloak.example.com",
		ClientID:  "test-client",
	}

	auth := New(config)

	// Create a mock HTTP client
	mockClient := &MockHTTPClientMiddleware{}
	mockClient.SetResponse(http.StatusOK, mockJWKSMiddleware)
	auth.SetHTTPClient(mockClient)

	// Setup test app with roles - this is now using Auth instead of ProtectWithRoles
	app := setupTestApp(auth.Auth(AuthOptions{
		Required: true,
		Roles:    []string{"admin", "editor"},
	}))

	// Test without token
	req := httptest.NewRequest("GET", "/test", nil)
	resp, err := app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
}

// TestAuthOptional tests the Auth middleware with optional auth
func TestAuthOptional(t *testing.T) {
	// Setup auth
	config := Config{
		Realm:     "test-realm",
		ServerURL: "https://keycloak.example.com",
		ClientID:  "test-client",
	}

	auth := New(config)

	// Create a mock HTTP client
	mockClient := &MockHTTPClientMiddleware{}
	mockClient.SetResponse(http.StatusOK, mockJWKSMiddleware)
	auth.SetHTTPClient(mockClient)

	// Setup test app - using Auth with Required=false instead of OptionalAuth
	app := fiber.New()
	app.Get("/test", auth.Auth(AuthOptions{
		Required: false,
	}), func(c *fiber.Ctx) error {
		if IsAuthenticated(c) {
			return c.SendString("authenticated")
		}
		return c.SendString("not authenticated")
	})

	// Test without token
	req := httptest.NewRequest("GET", "/test", nil)
	resp, err := app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "not authenticated", string(body))
}

// TestAuthAttributes tests the Auth middleware with attribute mapping
func TestAuthAttributes(t *testing.T) {
	// Setup auth
	config := Config{
		Realm:     "test-realm",
		ServerURL: "https://keycloak.example.com",
		ClientID:  "test-client",
	}

	auth := New(config)

	// Create a mock HTTP client
	mockClient := &MockHTTPClientMiddleware{}
	mockClient.SetResponse(http.StatusOK, mockJWKSMiddleware)
	auth.SetHTTPClient(mockClient)

	// Setup test app with attribute mappings
	app := setupTestApp(auth.Auth(AuthOptions{
		Required: true,
		AttributeMappings: []string{
			"preferred_username",
			"email",
			"attributes.organization",
		},
	}))

	// Test without token
	req := httptest.NewRequest("GET", "/test", nil)
	resp, err := app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
}

// TestAuthRoleBasedAttributes tests the Auth middleware with role-based attribute mapping
func TestAuthRoleBasedAttributes(t *testing.T) {
	// Setup auth
	config := Config{
		Realm:     "test-realm",
		ServerURL: "https://keycloak.example.com",
		ClientID:  "test-client",
	}

	auth := New(config)

	// Create a mock HTTP client
	mockClient := &MockHTTPClientMiddleware{}
	mockClient.SetResponse(http.StatusOK, mockJWKSMiddleware)
	auth.SetHTTPClient(mockClient)

	// Setup test app with role-based attribute mappings
	app := setupTestApp(auth.Auth(AuthOptions{
		Required: true,
		RoleMappings: []RoleAttributeMapping{
			{
				Role: "admin",
				AttributeMappings: []string{
					"preferred_username",
					"attributes.admin_level",
				},
			},
			{
				Role: "user",
				AttributeMappings: []string{
					"preferred_username",
					"attributes.subscription",
				},
			},
		},
	}))

	// Test without token
	req := httptest.NewRequest("GET", "/test", nil)
	resp, err := app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
}

// setupTestApp creates a test Fiber app with the provided handler
func setupTestApp(handler fiber.Handler) *fiber.App {
	app := fiber.New()
	app.Get("/test", handler, func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})
	return app
}
