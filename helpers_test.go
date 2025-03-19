package keycloakauth

import (
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"net/http/httptest"
)

// TestGetUser tests the GetUser helper function
func TestGetUser(t *testing.T) {
	app := fiber.New()

	// Test with user in context
	app.Get("/with-user", func(c *fiber.Ctx) error {
		c.Locals("user", &KeycloakClaims{
			PreferredUsername: "testuser",
			Email:             "test@example.com",
		})

		// Test GetUser
		user, ok := GetUser(c)
		assert.True(t, ok)
		assert.Equal(t, "testuser", user.PreferredUsername)
		assert.Equal(t, "test@example.com", user.Email)

		return c.SendString("OK")
	})

	// Test without user in context
	app.Get("/without-user", func(c *fiber.Ctx) error {
		// Test GetUser with no user in context
		user, ok := GetUser(c)
		assert.False(t, ok)
		assert.Nil(t, user)

		return c.SendString("OK")
	})

	// Run tests
	req := httptest.NewRequest("GET", "/with-user", nil)
	resp, err := app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	req = httptest.NewRequest("GET", "/without-user", nil)
	resp, err = app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)
}

// TestHasRole tests the HasRole helper function
func TestHasRole(t *testing.T) {
	app := fiber.New()

	// Test with roles
	app.Get("/with-roles", func(c *fiber.Ctx) error {
		// Create user with roles
		user := &KeycloakClaims{}
		user.RealmAccess.Roles = []string{"user", "admin"}

		// Store in context
		c.Locals("user", user)

		// Test HasRole
		assert.True(t, HasRole(c, "admin"))
		assert.True(t, HasRole(c, "user"))
		assert.False(t, HasRole(c, "editor"))

		return c.SendString("OK")
	})

	// Test without user
	app.Get("/without-user", func(c *fiber.Ctx) error {
		// Test HasRole with no user
		assert.False(t, HasRole(c, "admin"))

		return c.SendString("OK")
	})

	// Run tests
	req := httptest.NewRequest("GET", "/with-roles", nil)
	resp, err := app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	req = httptest.NewRequest("GET", "/without-user", nil)
	resp, err = app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)
}

// TestHasClientRole tests the HasClientRole helper function
func TestHasClientRole(t *testing.T) {
	app := fiber.New()

	// Test with client roles
	app.Get("/with-client-roles", func(c *fiber.Ctx) error {
		// Create user with client roles
		user := &KeycloakClaims{
			ResourceAccess: map[string]struct {
				Roles []string `json:"roles"`
			}(map[string]struct{ Roles []string }{
				"client1": {Roles: []string{"role1", "role2"}},
				"client2": {Roles: []string{"role3"}},
			}),
		}

		// Store in context
		c.Locals("user", user)

		// Test HasClientRole
		assert.True(t, HasClientRole(c, "client1", "role1"))
		assert.True(t, HasClientRole(c, "client1", "role2"))
		assert.True(t, HasClientRole(c, "client2", "role3"))
		assert.False(t, HasClientRole(c, "client1", "role3"))
		assert.False(t, HasClientRole(c, "client3", "role1"))

		return c.SendString("OK")
	})

	// Test without user
	app.Get("/without-user", func(c *fiber.Ctx) error {
		// Test HasClientRole with no user
		assert.False(t, HasClientRole(c, "client1", "role1"))

		return c.SendString("OK")
	})

	// Run tests
	req := httptest.NewRequest("GET", "/with-client-roles", nil)
	resp, err := app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	req = httptest.NewRequest("GET", "/without-user", nil)
	resp, err = app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)
}

// TestIsAuthenticated tests the IsAuthenticated helper function
func TestIsAuthenticated(t *testing.T) {
	app := fiber.New()

	// Test with user
	app.Get("/with-user", func(c *fiber.Ctx) error {
		c.Locals("user", &KeycloakClaims{})

		// Test IsAuthenticated
		assert.True(t, IsAuthenticated(c))

		return c.SendString("OK")
	})

	// Test without user
	app.Get("/without-user", func(c *fiber.Ctx) error {
		// Test IsAuthenticated with no user
		assert.False(t, IsAuthenticated(c))

		return c.SendString("OK")
	})

	// Run tests
	req := httptest.NewRequest("GET", "/with-user", nil)
	resp, err := app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	req = httptest.NewRequest("GET", "/without-user", nil)
	resp, err = app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)
}

// TestHasRequiredRoles tests the HasRequiredRoles helper function
func TestHasRequiredRoles(t *testing.T) {
	app := fiber.New()

	// Test with hasRequiredRoles = true
	app.Get("/with-required-roles", func(c *fiber.Ctx) error {
		c.Locals("hasRequiredRoles", true)

		// Test HasRequiredRoles
		assert.True(t, HasRequiredRoles(c))

		return c.SendString("OK")
	})

	// Test with hasRequiredRoles = false
	app.Get("/without-required-roles", func(c *fiber.Ctx) error {
		c.Locals("hasRequiredRoles", false)

		// Test HasRequiredRoles
		assert.False(t, HasRequiredRoles(c))

		return c.SendString("OK")
	})

	// Test without hasRequiredRoles
	app.Get("/no-required-roles-key", func(c *fiber.Ctx) error {
		// Test HasRequiredRoles with no hasRequiredRoles
		assert.False(t, HasRequiredRoles(c))

		return c.SendString("OK")
	})

	// Run tests
	req := httptest.NewRequest("GET", "/with-required-roles", nil)
	resp, err := app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	req = httptest.NewRequest("GET", "/without-required-roles", nil)
	resp, err = app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	req = httptest.NewRequest("GET", "/no-required-roles-key", nil)
	resp, err = app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)
}

// TestGetAttributeValue tests the GetAttributeValue helper function
func TestGetAttributeValue(t *testing.T) {
	app := fiber.New()

	// Test with attributes
	app.Get("/with-attributes", func(c *fiber.Ctx) error {
		// Create user with attributes
		user := &KeycloakClaims{
			PreferredUsername: "testuser",
			Email:             "test@example.com",
			Attributes: map[string]interface{}{
				"organization": "Test Org",
				"jobs": map[string]interface{}{
					"name": "Developer",
					"category": map[string]interface{}{
						"id": "123",
					},
				},
			},
		}

		// Store in context
		c.Locals("user", user)

		// Test GetAttributeValue for base properties
		value, ok := GetAttributeValue(c, "preferred_username")
		assert.True(t, ok)
		assert.Equal(t, "testuser", value)

		value, ok = GetAttributeValue(c, "email")
		assert.True(t, ok)
		assert.Equal(t, "test@example.com", value)

		// Test for attributes
		value, ok = GetAttributeValue(c, "attributes.organization")
		assert.True(t, ok)
		assert.Equal(t, "Test Org", value)

		// Test for nested attributes
		value, ok = GetAttributeValue(c, "attributes.jobs.name")
		assert.True(t, ok)
		assert.Equal(t, "Developer", value)

		value, ok = GetAttributeValue(c, "attributes.jobs.category.id")
		assert.True(t, ok)
		assert.Equal(t, "123", value)

		// Test for non-existent attributes
		value, ok = GetAttributeValue(c, "attributes.nonexistent")
		assert.False(t, ok)
		assert.Nil(t, value)

		return c.SendString("OK")
	})

	// Test without user
	app.Get("/without-user", func(c *fiber.Ctx) error {
		// Test GetAttributeValue with no user
		value, ok := GetAttributeValue(c, "attributes.organization")
		assert.False(t, ok)
		assert.Nil(t, value)

		return c.SendString("OK")
	})

	// Run tests
	req := httptest.NewRequest("GET", "/with-attributes", nil)
	resp, err := app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	req = httptest.NewRequest("GET", "/without-user", nil)
	resp, err = app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)
}

// TestGetMatchedRoles tests the GetMatchedRoles helper function
func TestGetMatchedRoles(t *testing.T) {
	app := fiber.New()

	// Test with matched roles
	app.Get("/with-matched-roles", func(c *fiber.Ctx) error {
		c.Locals("matched_roles", []string{"admin", "editor"})

		// Test GetMatchedRoles
		roles := GetMatchedRoles(c)
		assert.Equal(t, 2, len(roles))
		assert.Contains(t, roles, "admin")
		assert.Contains(t, roles, "editor")

		return c.SendString("OK")
	})

	// Test without matched roles
	app.Get("/without-matched-roles", func(c *fiber.Ctx) error {
		// Test GetMatchedRoles with no matched_roles
		roles := GetMatchedRoles(c)
		assert.Equal(t, 0, len(roles))

		return c.SendString("OK")
	})

	// Test with invalid matched roles
	app.Get("/invalid-matched-roles", func(c *fiber.Ctx) error {
		c.Locals("matched_roles", "not-a-slice")

		// Test GetMatchedRoles with invalid matched_roles
		roles := GetMatchedRoles(c)
		assert.Equal(t, 0, len(roles))

		return c.SendString("OK")
	})

	// Run tests
	req := httptest.NewRequest("GET", "/with-matched-roles", nil)
	resp, err := app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	req = httptest.NewRequest("GET", "/without-matched-roles", nil)
	resp, err = app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	req = httptest.NewRequest("GET", "/invalid-matched-roles", nil)
	resp, err = app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)
}
