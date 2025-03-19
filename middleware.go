package keycloakauth

import (
	"strings"

	"github.com/gofiber/fiber/v2"
)

// Auth adalah middleware terpadu untuk semua kebutuhan autentikasi dan otorisasi
func (k *KeycloakAuth) Auth(options AuthOptions) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Default: autentikasi diharuskan
		required := true
		if options.Required == false {
			required = false
		}

		// Cek jika ada header Authorization
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			// Jika autentikasi diharuskan tapi tidak ada token, return 401
			if required {
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
					"error": "missing authorization header",
				})
			}

			// Jika opsional, lanjutkan tanpa auth
			c.Locals("hasRequiredRoles", false)
			return c.Next()
		}

		// Coba ekstrak dan validasi token
		tokenString, err := extractTokenFromHeader(c)
		if err != nil {
			// Jika autentikasi diharuskan tapi format token salah, return 401
			if required {
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
					"error": err.Error(),
				})
			}

			// Jika opsional, lanjutkan tanpa auth
			c.Locals("hasRequiredRoles", false)
			return c.Next()
		}

		// Validasi token
		claims, err := k.validateToken(tokenString)
		if err != nil {
			// Jika autentikasi diharuskan tapi token invalid, return 401
			if required {
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
					"error": err.Error(),
				})
			}

			// Jika opsional, lanjutkan tanpa auth
			c.Locals("hasRequiredRoles", false)
			return c.Next()
		}

		// Token valid, simpan claims di context
		c.Locals("user", claims)

		// Jika tidak ada role yang ditentukan, cukup autentikasi
		// Jika ada RoleMappings, atur flag untuk cek nanti
		checkRoleMappings := len(options.RoleMappings) > 0

		// Jika ada roles yang ditentukan, periksa apakah pengguna memiliki salah satunya
		if len(options.Roles) > 0 {
			hasRole := false
			userRoles := getUserRoles(claims, k.config.ClientID)

			for _, role := range options.Roles {
				for _, userRole := range userRoles {
					if userRole == role {
						hasRole = true
						break
					}
				}
				if hasRole {
					break
				}
			}

			c.Locals("hasRequiredRoles", hasRole)

			// Jika autentikasi wajib dan pengguna tidak memiliki peran yang diperlukan, return 403
			if required && !hasRole && !checkRoleMappings {
				return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
					"error": "insufficient permissions",
				})
			}
		} else {
			// Tidak ada pemeriksaan role khusus
			c.Locals("hasRequiredRoles", true)
		}

		// Jika ada attribute mappings, map ke context
		if len(options.AttributeMappings) > 0 {
			for _, attrPath := range options.AttributeMappings {
				value := getNestedValue(claims, attrPath)
				if value != nil {
					// Gunakan bagian terakhir dari path sebagai key
					parts := strings.Split(attrPath, ".")
					key := parts[len(parts)-1]
					c.Locals(key, value)
				}
			}
		}

		// Jika ada role-based attribute mappings, terapkan
		if checkRoleMappings {
			userRoles := getUserRoles(claims, k.config.ClientID)
			hasDefinedRole := false

			for _, mapping := range options.RoleMappings {
				// Cek apakah pengguna memiliki role ini
				hasRole := false
				for _, userRole := range userRoles {
					if userRole == mapping.Role {
						hasRole = true
						hasDefinedRole = true
						break
					}
				}

				if hasRole {
					// Terapkan attribute mappings untuk role ini
					for _, attrPath := range mapping.AttributeMappings {
						value := getNestedValue(claims, attrPath)
						if value != nil {
							// Gunakan bagian terakhir dari path sebagai key
							parts := strings.Split(attrPath, ".")
							key := parts[len(parts)-1]
							c.Locals(key, value)
						}
					}

					// Catat role yang matched
					roleMatches := c.Locals("matched_roles")
					if roleMatches == nil {
						roleMatches = []string{mapping.Role}
					} else {
						roleMatches = append(roleMatches.([]string), mapping.Role)
					}
					c.Locals("matched_roles", roleMatches)
				}
			}

			// Jika tidak ada role yang matched dan autentikasi diharuskan, return 403
			if required && !hasDefinedRole && len(options.Roles) == 0 {
				return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
					"error": "insufficient permissions",
				})
			}
		}

		// Lanjutkan ke handler selanjutnya
		return c.Next()
	}
}

// Alias fungsi untuk backward compatibility - private, hanya digunakan secara internal

// protect adalah alias private untuk Auth dengan opsi default (wajib)
func (k *KeycloakAuth) protect() fiber.Handler {
	return k.Auth(AuthOptions{
		Required: true,
	})
}

// protectWithRole adalah alias private untuk Auth dengan satu role
func (k *KeycloakAuth) protectWithRole(role string) fiber.Handler {
	return k.Auth(AuthOptions{
		Required: true,
		Roles:    []string{role},
	})
}

// protectWithRoles adalah alias private untuk Auth dengan beberapa role
func (k *KeycloakAuth) protectWithRoles(roles []string) fiber.Handler {
	return k.Auth(AuthOptions{
		Required: true,
		Roles:    roles,
	})
}

// optionalAuth adalah alias private untuk Auth dengan autentikasi opsional
func (k *KeycloakAuth) optionalAuth() fiber.Handler {
	return k.Auth(AuthOptions{
		Required: false,
	})
}

// optionalAuthWithRoles adalah alias private untuk Auth dengan autentikasi opsional dan role
func (k *KeycloakAuth) optionalAuthWithRoles(roles []string) fiber.Handler {
	return k.Auth(AuthOptions{
		Required: false,
		Roles:    roles,
	})
}

// protectWithAttribute adalah alias private untuk Auth dengan attribute mapping
func (k *KeycloakAuth) protectWithAttribute(attributeMappings []string) fiber.Handler {
	return k.Auth(AuthOptions{
		Required:          true,
		AttributeMappings: attributeMappings,
	})
}

// protectWithRolesAndAttributes adalah alias private untuk Auth dengan role dan attribute
func (k *KeycloakAuth) protectWithRolesAndAttributes(roles []string, attributeMappings []string) fiber.Handler {
	return k.Auth(AuthOptions{
		Required:          true,
		Roles:             roles,
		AttributeMappings: attributeMappings,
	})
}

// protectWithRoleBasedAttributes adalah alias private untuk Auth dengan role-based attribute mapping
func (k *KeycloakAuth) protectWithRoleBasedAttributes(roleMappings []RoleAttributeMapping) fiber.Handler {
	return k.Auth(AuthOptions{
		Required:     true,
		RoleMappings: roleMappings,
	})
}
