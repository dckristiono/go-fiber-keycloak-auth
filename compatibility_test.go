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

// MockHTTPClientCompat implements HTTPClient interface for compatibility testing
type MockHTTPClientCompat struct {
	statusCode int
	response   string
}

func (m *MockHTTPClientCompat) Get(url string) (*http.Response, error) {
	return &http.Response{
		StatusCode: m.statusCode,
		Body:       io.NopCloser(strings.NewReader(m.response)),
	}, nil
}

func (m *MockHTTPClientCompat) SetResponse(statusCode int, response string) {
	m.statusCode = statusCode
	m.response = response
}

// JWKS mock for compatibility testing
const mockJWKSCompat = `{
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

// setupTestAppCompat creates a test Fiber app with the provided handler
func setupTestAppCompat(handler fiber.Handler) *fiber.App {
	app := fiber.New()
	app.Get("/test", handler, func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})
	return app
}

// TestBackwardCompatibility tests all backward compatibility functions
func TestBackwardCompatibility(t *testing.T) {
	// Setup auth
	config := Config{
		Realm:     "test-realm",
		ServerURL: "https://keycloak.example.com",
		ClientID:  "test-client",
	}

	auth := New(config)
	mockClient := &MockHTTPClientCompat{}
	mockClient.SetResponse(http.StatusOK, mockJWKSCompat)
	auth.SetHTTPClient(mockClient)

	// Test Protect
	app := setupTestAppCompat(auth.Protect())
	req := httptest.NewRequest("GET", "/test", nil)
	resp, err := app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)

	// Test ProtectWithRole
	app = setupTestAppCompat(auth.ProtectWithRole("admin"))
	req = httptest.NewRequest("GET", "/test", nil)
	resp, err = app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)

	// Test ProtectWithRoles
	app = setupTestAppCompat(auth.ProtectWithRoles([]string{"admin", "editor"}))
	req = httptest.NewRequest("GET", "/test", nil)
	resp, err = app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)

	// Test OptionalAuth
	app = setupTestAppCompat(auth.OptionalAuth())
	req = httptest.NewRequest("GET", "/test", nil)
	resp, err = app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	// Test OptionalAuthWithRoles
	app = setupTestAppCompat(auth.OptionalAuthWithRoles([]string{"admin"}))
	req = httptest.NewRequest("GET", "/test", nil)
	resp, err = app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	// Test ProtectWithAttribute
	app = setupTestAppCompat(auth.ProtectWithAttribute([]string{"preferred_username"}))
	req = httptest.NewRequest("GET", "/test", nil)
	resp, err = app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)

	// Test ProtectWithRolesAndAttributes
	app = setupTestAppCompat(auth.ProtectWithRolesAndAttributes(
		[]string{"admin"},
		[]string{"preferred_username"}))
	req = httptest.NewRequest("GET", "/test", nil)
	resp, err = app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)

	// Test ProtectWithRoleBasedAttributes
	app = setupTestAppCompat(auth.ProtectWithRoleBasedAttributes([]RoleAttributeMapping{
		{
			Role:              "admin",
			AttributeMappings: []string{"preferred_username"},
		},
	}))
	req = httptest.NewRequest("GET", "/test", nil)
	resp, err = app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
}

// TestCompatibilityFunctions_Detailed tests each compatibility function in detail
func TestCompatibilityFunctions_Detailed(t *testing.T) {
	// Setup auth
	config := Config{
		Realm:     "test-realm",
		ServerURL: "https://keycloak.example.com",
		ClientID:  "test-client",
	}

	auth := New(config)
	mockClient := &MockHTTPClientCompat{}
	mockClient.SetResponse(http.StatusOK, mockJWKSCompat)
	auth.SetHTTPClient(mockClient)

	// Test Protect() detailed
	app := fiber.New()
	app.Get("/protect", auth.Protect(), func(c *fiber.Ctx) error {
		// Verify that Required is set to true
		hasRequiredRoles := c.Locals("hasRequiredRoles")
		assert.Equal(t, nil, hasRequiredRoles) // Should be nil before evaluation
		return c.SendString("OK")
	})

	req := httptest.NewRequest("GET", "/protect", nil)
	resp, err := app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)

	// Test ProtectWithRole() detailed
	app = fiber.New()
	app.Get("/protect-with-role", auth.ProtectWithRole("admin"), func(c *fiber.Ctx) error {
		// Verify that Required is true and Roles contains "admin"
		return c.SendString("OK")
	})

	req = httptest.NewRequest("GET", "/protect-with-role", nil)
	resp, err = app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)

	// Test ProtectWithRoles() detailed
	roles := []string{"admin", "editor"}
	app = fiber.New()
	app.Get("/protect-with-roles", auth.ProtectWithRoles(roles), func(c *fiber.Ctx) error {
		// Verify that Required is true and Roles contains the specified roles
		return c.SendString("OK")
	})

	req = httptest.NewRequest("GET", "/protect-with-roles", nil)
	resp, err = app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)

	// Test OptionalAuth() detailed
	app = fiber.New()
	app.Get("/optional-auth", auth.OptionalAuth(), func(c *fiber.Ctx) error {
		// Verify that Required is false
		hasRequiredRoles := c.Locals("hasRequiredRoles")
		assert.Equal(t, false, hasRequiredRoles)
		return c.SendString("OK")
	})

	req = httptest.NewRequest("GET", "/optional-auth", nil)
	resp, err = app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	// Test OptionalAuthWithRoles() detailed
	app = fiber.New()
	app.Get("/optional-auth-with-roles", auth.OptionalAuthWithRoles(roles), func(c *fiber.Ctx) error {
		// Verify that Required is false and Roles contains the specified roles
		hasRequiredRoles := c.Locals("hasRequiredRoles")
		assert.Equal(t, false, hasRequiredRoles)
		return c.SendString("OK")
	})

	req = httptest.NewRequest("GET", "/optional-auth-with-roles", nil)
	resp, err = app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	// Test ProtectWithAttribute() detailed
	attributeMappings := []string{"preferred_username", "email"}
	app = fiber.New()
	app.Get("/protect-with-attribute", auth.ProtectWithAttribute(attributeMappings), func(c *fiber.Ctx) error {
		// Verify that Required is true and AttributeMappings contains the specified mappings
		return c.SendString("OK")
	})

	req = httptest.NewRequest("GET", "/protect-with-attribute", nil)
	resp, err = app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)

	// Test ProtectWithRolesAndAttributes() detailed
	app = fiber.New()
	app.Get("/protect-with-roles-and-attributes", auth.ProtectWithRolesAndAttributes(roles, attributeMappings), func(c *fiber.Ctx) error {
		// Verify that Required is true, Roles contains the specified roles,
		// and AttributeMappings contains the specified mappings
		return c.SendString("OK")
	})

	req = httptest.NewRequest("GET", "/protect-with-roles-and-attributes", nil)
	resp, err = app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)

	// Test ProtectWithRoleBasedAttributes() detailed
	roleMappings := []RoleAttributeMapping{
		{
			Role:              "admin",
			AttributeMappings: []string{"preferred_username", "email"},
		},
	}
	app = fiber.New()
	app.Get("/protect-with-role-based-attributes", auth.ProtectWithRoleBasedAttributes(roleMappings), func(c *fiber.Ctx) error {
		// Verify that Required is true and RoleMappings contains the specified mappings
		return c.SendString("OK")
	})

	req = httptest.NewRequest("GET", "/protect-with-role-based-attributes", nil)
	resp, err = app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
}

// TestBackwardCompatibilityWithToken tests all compatibility functions with a token
func TestBackwardCompatibilityWithToken(t *testing.T) {
	// Setup auth
	config := Config{
		Realm:     "test-realm",
		ServerURL: "https://keycloak.example.com",
		ClientID:  "test-client",
	}

	auth := New(config)
	mockClient := &MockHTTPClientCompat{}
	mockClient.SetResponse(http.StatusOK, mockJWKSCompat)
	auth.SetHTTPClient(mockClient)

	// For each compatibility function, test with an invalid token
	testCases := []struct {
		name     string
		handler  fiber.Handler
		required bool
	}{
		{"Protect", auth.Protect(), true},
		{"ProtectWithRole", auth.ProtectWithRole("admin"), true},
		{"ProtectWithRoles", auth.ProtectWithRoles([]string{"admin", "editor"}), true},
		{"OptionalAuth", auth.OptionalAuth(), false},
		{"OptionalAuthWithRoles", auth.OptionalAuthWithRoles([]string{"admin"}), false},
		{"ProtectWithAttribute", auth.ProtectWithAttribute([]string{"username"}), true},
		{"ProtectWithRolesAndAttributes", auth.ProtectWithRolesAndAttributes(
			[]string{"admin"}, []string{"username"}), true},
		{"ProtectWithRoleBasedAttributes", auth.ProtectWithRoleBasedAttributes([]RoleAttributeMapping{
			{Role: "admin", AttributeMappings: []string{"username"}},
		}), true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			app := setupTestAppCompat(tc.handler)

			// Test with invalid token
			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set("Authorization", "Bearer InvalidToken")
			resp, err := app.Test(req)
			assert.NoError(t, err)

			if tc.required {
				assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
			} else {
				assert.Equal(t, fiber.StatusOK, resp.StatusCode)
			}
		})
	}
}

// TestDynamicRoleAssignment tests role assignment dynamically
func TestDynamicRoleAssignment(t *testing.T) {
	// Setup auth
	config := Config{
		Realm:     "test-realm",
		ServerURL: "https://keycloak.example.com",
		ClientID:  "test-client",
	}

	auth := New(config)
	mockClient := &MockHTTPClientCompat{}
	mockClient.SetResponse(http.StatusOK, mockJWKSCompat)
	auth.SetHTTPClient(mockClient)

	// Test with dynamic role assignments
	dynamicRoles := []string{"role1", "role2", "role3"}

	app := setupTestAppCompat(auth.ProtectWithRoles(dynamicRoles))

	req := httptest.NewRequest("GET", "/test", nil)
	resp, err := app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)

	// Test with dynamic attribute mappings
	dynamicAttributes := []string{"attr1", "attr2", "attr3"}

	app = setupTestAppCompat(auth.ProtectWithAttribute(dynamicAttributes))

	req = httptest.NewRequest("GET", "/test", nil)
	resp, err = app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
}
