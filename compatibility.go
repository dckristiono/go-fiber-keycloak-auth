package keycloakauth

import "github.com/gofiber/fiber/v2"

// Fungsi-fungsi berikut disediakan untuk backward compatibility
// dengan kode yang mungkin telah menggunakan API sebelumnya.

// Protect adalah alias untuk Auth dengan opsi default (wajib)
func (k *KeycloakAuth) Protect() fiber.Handler {
	return k.Auth(AuthOptions{
		Required: true,
	})
}

// ProtectWithRole adalah alias untuk Auth dengan satu role
func (k *KeycloakAuth) ProtectWithRole(role string) fiber.Handler {
	return k.Auth(AuthOptions{
		Required: true,
		Roles:    []string{role},
	})
}

// ProtectWithRoles adalah alias untuk Auth dengan beberapa role
func (k *KeycloakAuth) ProtectWithRoles(roles []string) fiber.Handler {
	return k.Auth(AuthOptions{
		Required: true,
		Roles:    roles,
	})
}

// OptionalAuth adalah alias untuk Auth dengan autentikasi opsional
func (k *KeycloakAuth) OptionalAuth() fiber.Handler {
	return k.Auth(AuthOptions{
		Required: false,
	})
}

// OptionalAuthWithRoles adalah alias untuk Auth dengan autentikasi opsional dan role
func (k *KeycloakAuth) OptionalAuthWithRoles(roles []string) fiber.Handler {
	return k.Auth(AuthOptions{
		Required: false,
		Roles:    roles,
	})
}

// ProtectWithAttribute adalah alias untuk Auth dengan attribute mapping
func (k *KeycloakAuth) ProtectWithAttribute(attributeMappings []string) fiber.Handler {
	return k.Auth(AuthOptions{
		Required:          true,
		AttributeMappings: attributeMappings,
	})
}

// ProtectWithRolesAndAttributes adalah alias untuk Auth dengan role dan attribute
func (k *KeycloakAuth) ProtectWithRolesAndAttributes(roles []string, attributeMappings []string) fiber.Handler {
	return k.Auth(AuthOptions{
		Required:          true,
		Roles:             roles,
		AttributeMappings: attributeMappings,
	})
}

// ProtectWithRoleBasedAttributes adalah alias untuk Auth dengan role-based attribute mapping
func (k *KeycloakAuth) ProtectWithRoleBasedAttributes(roleMappings []RoleAttributeMapping) fiber.Handler {
	return k.Auth(AuthOptions{
		Required:     true,
		RoleMappings: roleMappings,
	})
}
