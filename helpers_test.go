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

	// Test with wrong type in context
	app.Get("/wrong-type", func(c *fiber.Ctx) error {
		c.Locals("user", "not-a-user-object")

		// Test GetUser with wrong type in context
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

	req = httptest.NewRequest("GET", "/wrong-type", nil)
	resp, err = app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)
}

// TestHasRole tests the HasRole helper function
func TestHasRole(t *testing.T) {
	app := fiber.New()

	// Test with roles
	app.Get("/with-roles", func(c *fiber.Ctx) error {
		// Create user with realm roles
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

	// Test with empty roles
	app.Get("/empty-roles", func(c *fiber.Ctx) error {
		// Create user with empty roles
		user := &KeycloakClaims{}
		user.RealmAccess.Roles = []string{}

		// Store in context
		c.Locals("user", user)

		// Test HasRole with empty roles
		assert.False(t, HasRole(c, "admin"))

		return c.SendString("OK")
	})

	// Test without user
	app.Get("/without-user", func(c *fiber.Ctx) error {
		// Test HasRole with no user
		assert.False(t, HasRole(c, "admin"))

		return c.SendString("OK")
	})

	// Test with nil roles
	app.Get("/nil-roles", func(c *fiber.Ctx) error {
		// Create user with nil roles array
		user := &KeycloakClaims{}
		user.RealmAccess.Roles = nil

		// Store in context
		c.Locals("user", user)

		// Test HasRole with nil roles
		assert.False(t, HasRole(c, "admin"))

		return c.SendString("OK")
	})

	// Run tests
	req := httptest.NewRequest("GET", "/with-roles", nil)
	resp, err := app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	req = httptest.NewRequest("GET", "/empty-roles", nil)
	resp, err = app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	req = httptest.NewRequest("GET", "/without-user", nil)
	resp, err = app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	req = httptest.NewRequest("GET", "/nil-roles", nil)
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
			}{
				"client1": {Roles: []string{"role1", "role2"}},
				"client2": {Roles: []string{"role3"}},
			},
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

	// Test with empty client roles
	app.Get("/empty-client-roles", func(c *fiber.Ctx) error {
		// Create user with empty client roles
		user := &KeycloakClaims{
			ResourceAccess: map[string]struct {
				Roles []string `json:"roles"`
			}{
				"client1": {Roles: []string{}},
			},
		}

		// Store in context
		c.Locals("user", user)

		// Test HasClientRole with empty roles
		assert.False(t, HasClientRole(c, "client1", "role1"))

		return c.SendString("OK")
	})

	// Test with nil ResourceAccess
	app.Get("/nil-resource-access", func(c *fiber.Ctx) error {
		// Create user with nil ResourceAccess
		user := &KeycloakClaims{
			ResourceAccess: nil,
		}

		// Store in context
		c.Locals("user", user)

		// Test HasClientRole with nil ResourceAccess
		assert.False(t, HasClientRole(c, "client1", "role1"))

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

	req = httptest.NewRequest("GET", "/empty-client-roles", nil)
	resp, err = app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	req = httptest.NewRequest("GET", "/nil-resource-access", nil)
	resp, err = app.Test(req)
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

	// Test with wrong type
	app.Get("/wrong-type", func(c *fiber.Ctx) error {
		c.Locals("hasRequiredRoles", "not-a-bool")

		// Test HasRequiredRoles with wrong type
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

	req = httptest.NewRequest("GET", "/wrong-type", nil)
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
				"null_value":   nil,
				"zero_value":   0,
				"empty_string": "",
				"empty_array":  []interface{}{},
				"empty_map":    map[string]interface{}{},
			},
			OtherClaims: map[string]interface{}{
				"string_map": map[string]string{
					"key": "value",
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

		// Test for empty path
		value, ok = GetAttributeValue(c, "")
		assert.False(t, ok)
		assert.Nil(t, value)

		// Test for invalid type in path
		value, ok = GetAttributeValue(c, "attributes.jobs.name.invalid")
		assert.False(t, ok)
		assert.Nil(t, value)

		// Test with string map
		value, ok = GetAttributeValue(c, "string_map.key")
		assert.True(t, ok)
		assert.Equal(t, "value", value)

		// Test edge cases
		value, ok = GetAttributeValue(c, "attributes.null_value")
		assert.False(t, ok) // Null values should return false
		assert.Nil(t, value)

		value, ok = GetAttributeValue(c, "attributes.zero_value")
		assert.True(t, ok)
		assert.Equal(t, 0, value)

		value, ok = GetAttributeValue(c, "attributes.empty_string")
		assert.True(t, ok)
		assert.Equal(t, "", value)

		value, ok = GetAttributeValue(c, "attributes.empty_array")
		assert.True(t, ok)
		assert.Equal(t, []interface{}{}, value)

		value, ok = GetAttributeValue(c, "attributes.empty_map")
		assert.True(t, ok)
		assert.Equal(t, map[string]interface{}{}, value)

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

	// Test with map instead of slice
	app.Get("/map-roles", func(c *fiber.Ctx) error {
		// Set a map instead of a slice
		c.Locals("matched_roles", map[string]string{"role": "admin"})

		// Test GetMatchedRoles
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

	req = httptest.NewRequest("GET", "/map-roles", nil)
	resp, err = app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)
}

// TestGetUserRoles tests the getUserRoles helper function
func TestGetUserRoles(t *testing.T) {
	// Test with both realm and client roles
	claims := &KeycloakClaims{}
	claims.RealmAccess.Roles = []string{"user", "admin"}
	claims.ResourceAccess = map[string]struct {
		Roles []string `json:"roles"`
	}{
		"client1": {Roles: []string{"role1", "role2"}},
	}

	roles := getUserRoles(claims, "client1")
	assert.Equal(t, 4, len(roles))
	assert.Contains(t, roles, "user")
	assert.Contains(t, roles, "admin")
	assert.Contains(t, roles, "role1")
	assert.Contains(t, roles, "role2")

	// Test with only realm roles
	claims = &KeycloakClaims{}
	claims.RealmAccess.Roles = []string{"user", "admin"}
	claims.ResourceAccess = nil

	roles = getUserRoles(claims, "client1")
	assert.Equal(t, 2, len(roles))
	assert.Contains(t, roles, "user")
	assert.Contains(t, roles, "admin")

	// Test with only client roles
	claims = &KeycloakClaims{}
	claims.RealmAccess.Roles = []string{}
	claims.ResourceAccess = map[string]struct {
		Roles []string `json:"roles"`
	}{
		"client1": {Roles: []string{"role1", "role2"}},
	}

	roles = getUserRoles(claims, "client1")
	assert.Equal(t, 2, len(roles))
	assert.Contains(t, roles, "role1")
	assert.Contains(t, roles, "role2")

	// Test with different client ID
	claims = &KeycloakClaims{}
	claims.RealmAccess.Roles = []string{"user", "admin"}
	claims.ResourceAccess = map[string]struct {
		Roles []string `json:"roles"`
	}{
		"client1": {Roles: []string{"role1", "role2"}},
	}

	roles = getUserRoles(claims, "client2")
	assert.Equal(t, 2, len(roles))
	assert.Contains(t, roles, "user")
	assert.Contains(t, roles, "admin")

	// Test with no roles
	claims = &KeycloakClaims{}
	claims.RealmAccess.Roles = []string{}
	claims.ResourceAccess = nil

	roles = getUserRoles(claims, "client1")
	assert.Equal(t, 0, len(roles))

	// Test with nil roles
	claims = &KeycloakClaims{}
	claims.RealmAccess.Roles = nil
	claims.ResourceAccess = nil

	roles = getUserRoles(claims, "client1")
	assert.Equal(t, 0, len(roles))

	// Test with duplicated roles
	claims = &KeycloakClaims{}
	claims.RealmAccess.Roles = []string{"role1", "role2"}
	claims.ResourceAccess = map[string]struct {
		Roles []string `json:"roles"`
	}{
		"client1": {Roles: []string{"role1", "role3"}}, // role1 is duplicated
	}

	roles = getUserRoles(claims, "client1")
	assert.Equal(t, 4, len(roles)) // Includes duplicates

	// Count occurrences of role1
	count := 0
	for _, role := range roles {
		if role == "role1" {
			count++
		}
	}
	assert.Equal(t, 2, count) // role1 appears twice
}

// TestGetNestedValue tests the getNestedValue helper function
func TestGetNestedValue(t *testing.T) {
	// Create user with attributes
	claims := &KeycloakClaims{
		PreferredUsername: "testuser",
		Email:             "test@example.com",
		EmailVerified:     true,
		GivenName:         "Test",
		FamilyName:        "User",
		Attributes: map[string]interface{}{
			"organization": "Test Org",
			"jobs": map[string]interface{}{
				"name": "Developer",
				"category": map[string]interface{}{
					"id": "123",
				},
			},
		},
		OtherClaims: map[string]interface{}{
			"custom_claim": "custom_value",
			"nested_claim": map[string]interface{}{
				"key": "value",
			},
			"string_map": map[string]string{
				"key": "value",
			},
		},
	}

	// Test root level properties - yang penting EKSPEKTASI menyesuaikan implementasi
	value := getNestedValue(claims, "preferred_username")
	assert.Equal(t, "testuser", value) // Ekspektasi yang benar: mengembalikan "testuser"

	value = getNestedValue(claims, "email")
	assert.Equal(t, "test@example.com", value)

	value = getNestedValue(claims, "email_verified")
	assert.Equal(t, true, value)

	value = getNestedValue(claims, "given_name")
	assert.Equal(t, "Test", value)

	value = getNestedValue(claims, "family_name")
	assert.Equal(t, "User", value)

	// Test attributes
	value = getNestedValue(claims, "attributes.organization")
	assert.Equal(t, "Test Org", value)

	// Test nested attributes
	value = getNestedValue(claims, "attributes.jobs.name")
	assert.Equal(t, "Developer", value)

	value = getNestedValue(claims, "attributes.jobs.category.id")
	assert.Equal(t, "123", value)

	// Test other claims
	value = getNestedValue(claims, "custom_claim")
	assert.Equal(t, "custom_value", value)

	value = getNestedValue(claims, "nested_claim.key")
	assert.Equal(t, "value", value)

	// Test with string map in other claims
	value = getNestedValue(claims, "string_map.key")
	assert.Equal(t, "value", value)

	// Test non-existent paths
	value = getNestedValue(claims, "nonexistent")
	assert.Nil(t, value)

	value = getNestedValue(claims, "attributes.nonexistent")
	assert.Nil(t, value)

	value = getNestedValue(claims, "attributes.jobs.nonexistent")
	assert.Nil(t, value)

	// Test empty path
	value = getNestedValue(claims, "")
	assert.Nil(t, value)

	// Test with path that doesn't map to a map
	value = getNestedValue(claims, "preferred_username")
	assert.Equal(t, "testuser", value)
}

// TestGetNestedValue_EdgeCases menguji kasus-kasus batas untuk getNestedValue
func TestGetNestedValue_EdgeCases(t *testing.T) {
	// Konfigurasi claims dengan berbagai tipe dan struktur data
	claims := &KeycloakClaims{
		PreferredUsername: "testuser",
		Email:             "test@example.com",
		EmailVerified:     true,
		GivenName:         "Test",
		FamilyName:        "User",
		Attributes: map[string]interface{}{
			"nil_value":    nil,
			"empty_map":    map[string]interface{}{},
			"empty_slice":  []interface{}{},
			"numeric":      42,
			"boolean":      true,
			"string_slice": []string{"one", "two", "three"},
			"mixed_slice":  []interface{}{1, "two", true, nil},
			"nested": map[string]interface{}{
				"nil_nested":   nil,
				"empty_nested": map[string]interface{}{},
				"deep_nested": map[string]interface{}{
					"very_deep": map[string]interface{}{
						"ultra_deep": "found me!",
					},
				},
			},
		},
		OtherClaims: map[string]interface{}{
			"string_map": map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
			"with_nil": map[string]interface{}{
				"nil_value": nil,
			},
		},
	}

	// 1. Test kasus nil di tengah path
	value := getNestedValue(claims, "attributes.nil_value.something")
	assert.Nil(t, value)

	// 2. Test path yang berakhir dengan nilai nil
	value = getNestedValue(claims, "attributes.nil_value")
	assert.Nil(t, value)

	// 3. Test mengakses elemen dari slice (seharusnya nil karena slice tidak didukung)
	value = getNestedValue(claims, "attributes.string_slice.0")
	assert.Nil(t, value)

	// 4. Test mengakses map di dalam slice (tidak didukung)
	value = getNestedValue(claims, "attributes.mixed_slice.map_key")
	assert.Nil(t, value)

	// 5. Test path yang sangat dalam
	value = getNestedValue(claims, "attributes.nested.deep_nested.very_deep.ultra_deep")
	assert.Equal(t, "found me!", value)

	// 6. Test dengan path yang valid diikuti dengan path yang tidak valid
	value = getNestedValue(claims, "attributes.numeric.invalid")
	assert.Nil(t, value)

	// 7. Test dengan interface map
	// Map dengan interface keys tidak didukung secara langsung dalam getNestedValue
	value = getNestedValue(claims, "interface_map.key")
	assert.Nil(t, value)

	// 8. Test dengan map[string]string vs map[string]interface{}
	value = getNestedValue(claims, "string_map.key1")
	assert.Equal(t, "value1", value)

	// 9. Test dengan path yang berakhir dengan empty map
	value = getNestedValue(claims, "attributes.empty_map")
	assert.Equal(t, map[string]interface{}{}, value)

	// 10. Test dengan path yang berakhir dengan empty slice
	value = getNestedValue(claims, "attributes.empty_slice")
	assert.Equal(t, []interface{}{}, value)

	// Test dengan empty claims (bukan nil)
	emptyClaims := &KeycloakClaims{}
	value = getNestedValue(emptyClaims, "any.path")
	assert.Nil(t, value)
}

// TestGetNestedValue_SafeNilChecks verifikasi bahwa kode tidak panic dengan input yang invalid
func TestGetNestedValue_SafeNilChecks(t *testing.T) {
	// Test dengan path kosong
	claims := &KeycloakClaims{}
	value := getNestedValue(claims, "")
	assert.Nil(t, value)

	// Test dengan nil di tengah path yang menghindari dereferensi nil
	claims = &KeycloakClaims{
		Attributes: map[string]interface{}{
			"test": nil,
		},
	}
	value = getNestedValue(claims, "attributes.test.nonexistent")
	assert.Nil(t, value)
}
