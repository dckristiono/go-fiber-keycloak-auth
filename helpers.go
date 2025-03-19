package keycloakauth

import (
	"strings"

	"github.com/gofiber/fiber/v2"
)

// GetUser extracts the user information from the context
func GetUser(c *fiber.Ctx) (*KeycloakClaims, bool) {
	user, ok := c.Locals("user").(*KeycloakClaims)
	return user, ok
}

// HasRole checks if the user has a specific role
func HasRole(c *fiber.Ctx, role string) bool {
	user, ok := GetUser(c)
	if !ok {
		return false
	}

	// Check realm roles
	for _, r := range user.RealmAccess.Roles {
		if r == role {
			return true
		}
	}

	return false
}

// HasClientRole checks if the user has a specific client role
func HasClientRole(c *fiber.Ctx, clientID, role string) bool {
	user, ok := GetUser(c)
	if !ok {
		return false
	}

	// Check client roles
	if clientRoles, exists := user.ResourceAccess[clientID]; exists {
		for _, r := range clientRoles.Roles {
			if r == role {
				return true
			}
		}
	}

	return false
}

// IsAuthenticated checks if the user is authenticated
func IsAuthenticated(c *fiber.Ctx) bool {
	_, ok := GetUser(c)
	return ok
}

// HasRequiredRoles checks if the user has any of the required roles (for optional auth)
func HasRequiredRoles(c *fiber.Ctx) bool {
	hasRoles, ok := c.Locals("hasRequiredRoles").(bool)
	return ok && hasRoles
}

// GetAttributeValue gets a specific attribute value from user claims using dot notation
func GetAttributeValue(c *fiber.Ctx, path string) (interface{}, bool) {
	user, ok := GetUser(c)
	if !ok {
		return nil, false
	}

	value := getNestedValue(user, path)
	return value, value != nil
}

// GetMatchedRoles gets the list of roles that matched in role-based attribute mapping
func GetMatchedRoles(c *fiber.Ctx) []string {
	roles, ok := c.Locals("matched_roles").([]string)
	if !ok {
		return []string{}
	}
	return roles
}

// getUserRoles combines realm roles and client roles for easier checking (private)
func getUserRoles(claims *KeycloakClaims, clientID string) []string {
	var roles []string

	// Add realm roles
	roles = append(roles, claims.RealmAccess.Roles...)

	// Add client roles if they exist
	if claims.ResourceAccess != nil {
		if clientRoles, exists := claims.ResourceAccess[clientID]; exists {
			roles = append(roles, clientRoles.Roles...)
		}
	}

	return roles
}

// getNestedValue extracts a value from nested maps using a dot-separated path (private)
// Example: "attributes.jobs.name" will get claims.attributes["jobs"]["name"]
func getNestedValue(claims *KeycloakClaims, path string) interface{} {
	parts := strings.Split(path, ".")
	if len(parts) == 0 {
		return nil
	}

	// Start with the root property
	var current interface{}
	rootKey := parts[0]

	// Handle root level properties
	switch rootKey {
	case "preferred_username":
		return claims.PreferredUsername
	case "given_name":
		return claims.GivenName
	case "family_name":
		return claims.FamilyName
	case "email":
		return claims.Email
	case "email_verified":
		return claims.EmailVerified
	case "attributes":
		current = claims.Attributes
	default:
		// Try to get from OtherClaims
		if val, ok := claims.OtherClaims[rootKey]; ok {
			current = val
		} else {
			return nil
		}
	}

	// If path is just a single part, return the value
	if len(parts) == 1 {
		return current
	}

	// Handle nested properties
	for i := 1; i < len(parts); i++ {
		// Convert current to map if possible
		currentMap, ok := current.(map[string]interface{})
		if !ok {
			// Try type assertion for different map types
			if currentMapString, ok := current.(map[string]string); ok {
				// Convert map[string]string to map[string]interface{}
				currentMap = make(map[string]interface{})
				for k, v := range currentMapString {
					currentMap[k] = v
				}
			} else {
				// Not a map, can't go deeper
				return nil
			}
		}

		// Get next level
		current = currentMap[parts[i]]
		if current == nil {
			return nil
		}
	}

	return current
}
