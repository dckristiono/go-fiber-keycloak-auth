package main

import (
	"log"

	"github.com/dckristiono/go-fiber-keycloak-auth"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
)

func main() {
	// Inisialisasi aplikasi GoFiber dengan logger
	app := fiber.New()
	app.Use(logger.New())

	// Konfigurasi Keycloak
	keycloakConfig := keycloakauth.Config{
		Realm:     "my-realm",
		ServerURL: "http://localhost:8080/auth",
		ClientID:  "my-client",
		CacheJWKS: true,
	}

	// Buat instance KeycloakAuth
	auth := keycloakauth.New(keycloakConfig)

	// -------------------------------
	// CONTOH MENGGUNAKAN MIDDLEWARE TERPADU
	// -------------------------------

	// 1. Route publik - tanpa middleware
	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("Halaman Publik - Dapat diakses siapa saja")
	})

	// 2. Autentikasi wajib sederhana
	app.Get("/profile", auth.Auth(keycloakauth.AuthOptions{
		Required: true,
	}), func(c *fiber.Ctx) error {
		user, _ := keycloakauth.GetUser(c)
		return c.JSON(fiber.Map{
			"message":  "Profil Pengguna",
			"username": user.PreferredUsername,
		})
	})

	// 3. Autentikasi opsional
	app.Get("/dashboard", auth.Auth(keycloakauth.AuthOptions{
		Required: false,
	}), func(c *fiber.Ctx) error {
		if !keycloakauth.IsAuthenticated(c) {
			return c.SendString("Dashboard Publik - Silakan login untuk fitur tambahan")
		}

		user, _ := keycloakauth.GetUser(c)
		return c.JSON(fiber.Map{
			"message":  "Dashboard Pengguna Terautentikasi",
			"username": user.PreferredUsername,
		})
	})

	// 4. Persyaratan role
	app.Get("/admin", auth.Auth(keycloakauth.AuthOptions{
		Required: true,
		Roles:    []string{"admin", "super-admin"},
	}), func(c *fiber.Ctx) error {
		user, _ := keycloakauth.GetUser(c)
		return c.JSON(fiber.Map{
			"message":  "Halaman Admin",
			"username": user.PreferredUsername,
		})
	})

	// 5. Attribute mapping
	app.Get("/attributes", auth.Auth(keycloakauth.AuthOptions{
		Required: true,
		AttributeMappings: []string{
			"preferred_username",
			"email",
			"attributes.organization",
		},
	}), func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"message":      "Atribut Pengguna",
			"username":     c.Locals("preferred_username"),
			"email":        c.Locals("email"),
			"organization": c.Locals("organization"),
		})
	})

	// 6. Role-based attribute mapping
	app.Get("/role-attributes", auth.Auth(keycloakauth.AuthOptions{
		Required: true,
		RoleMappings: []keycloakauth.RoleAttributeMapping{
			{
				Role: "admin",
				AttributeMappings: []string{
					"preferred_username",
					"email",
					"attributes.admin_level",
					"attributes.permissions",
				},
			},
			{
				Role: "user",
				AttributeMappings: []string{
					"preferred_username",
					"email",
					"attributes.subscription",
				},
			},
		},
	}), func(c *fiber.Ctx) error {
		matchedRoles := keycloakauth.GetMatchedRoles(c)

		response := fiber.Map{
			"message":       "Role-Based Attributes",
			"username":      c.Locals("preferred_username"),
			"matched_roles": matchedRoles,
		}

		// Tambahkan atribut khusus role jika tersedia
		if adminLevel := c.Locals("admin_level"); adminLevel != nil {
			response["admin_level"] = adminLevel
		}

		if permissions := c.Locals("permissions"); permissions != nil {
			response["permissions"] = permissions
		}

		if subscription := c.Locals("subscription"); subscription != nil {
			response["subscription"] = subscription
		}

		return c.JSON(response)
	})

	// 7. Kombinasi fitur
	app.Get("/complex", auth.Auth(keycloakauth.AuthOptions{
		Required: false,               // Autentikasi opsional
		Roles:    []string{"premium"}, // Cek role ini
		AttributeMappings: []string{ // Attribute umum
			"preferred_username",
			"email",
		},
		RoleMappings: []keycloakauth.RoleAttributeMapping{ // Attribute khusus per role
			{
				Role: "admin",
				AttributeMappings: []string{
					"attributes.admin_level",
				},
			},
			{
				Role: "premium",
				AttributeMappings: []string{
					"attributes.subscription_level",
				},
			},
		},
	}), func(c *fiber.Ctx) error {
		if !keycloakauth.IsAuthenticated(c) {
			return c.SendString("Halaman Publik Kompleks")
		}

		response := fiber.Map{
			"username":           c.Locals("preferred_username"),
			"email":              c.Locals("email"),
			"matched_roles":      keycloakauth.GetMatchedRoles(c),
			"has_required_roles": keycloakauth.HasRequiredRoles(c),
		}

		// Atribut khusus per role
		if adminLevel := c.Locals("admin_level"); adminLevel != nil {
			response["admin_level"] = adminLevel
		}

		if subscriptionLevel := c.Locals("subscription_level"); subscriptionLevel != nil {
			response["subscription_level"] = subscriptionLevel
		}

		return c.JSON(response)
	})

	// Mulai server
	log.Fatal(app.Listen(":3002"))
}
