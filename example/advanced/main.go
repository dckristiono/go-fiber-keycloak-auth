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
	// CONTOH ROUTE LANJUTAN (menggunakan Auth terpadu)
	// -------------------------------

	// 1. Route dengan Mapping Attribute
	// Lama: auth.ProtectWithRolesAndAttributes([]string{"user", "admin"}, []string{...})
	// Baru: auth.Auth({Required: true, Roles: []string{"user", "admin"}, AttributeMappings: []string{...}})
	app.Get("/user-detail", auth.Auth(keycloakauth.AuthOptions{
		Required: true,
		Roles:    []string{"user", "admin"},
		AttributeMappings: []string{
			"preferred_username",
			"email",
			"attributes.organization",
			"attributes.jobs.name",
			"attributes.jobs.category.id",
		},
	}), func(c *fiber.Ctx) error {
		username := c.Locals("preferred_username")
		email := c.Locals("email")
		organization := c.Locals("organization")
		jobName := c.Locals("name")
		jobCategoryId := c.Locals("id")

		return c.JSON(fiber.Map{
			"message":         "Detail Pengguna",
			"username":        username,
			"email":           email,
			"organization":    organization,
			"job_name":        jobName,
			"job_category_id": jobCategoryId,
		})
	})

	// 2. Contoh pengambilan data attribute secara manual
	// Lama: auth.Protect()
	// Baru: auth.Auth({Required: true})
	app.Get("/manual-attributes", auth.Auth(keycloakauth.AuthOptions{
		Required: true,
	}), func(c *fiber.Ctx) error {
		// Mengambil nilai attribute secara manual
		organization, orgOk := keycloakauth.GetAttributeValue(c, "attributes.organization")
		jobName, jobOk := keycloakauth.GetAttributeValue(c, "attributes.jobs.name")

		return c.JSON(fiber.Map{
			"has_organization": orgOk,
			"organization":     organization,
			"has_job_name":     jobOk,
			"job_name":         jobName,
		})
	})

	// 3. Role-based Attribute Mapping
	// Lama: auth.ProtectWithRoleBasedAttributes([]RoleAttributeMapping{...})
	// Baru: auth.Auth({Required: true, RoleMappings: []RoleAttributeMapping{...}})
	app.Get("/role-based", auth.Auth(keycloakauth.AuthOptions{
		Required: true,
		RoleMappings: []keycloakauth.RoleAttributeMapping{
			{
				Role: "admin",
				AttributeMappings: []string{
					"preferred_username",
					"email",
					"attributes.admin_level",
					"attributes.admin_permissions",
					"attributes.security_clearance",
				},
			},
			{
				Role: "user",
				AttributeMappings: []string{
					"preferred_username",
					"email",
					"attributes.user_type",
					"attributes.subscription_level",
				},
			},
			{
				Role: "editor",
				AttributeMappings: []string{
					"preferred_username",
					"email",
					"attributes.content_areas",
					"attributes.allowed_sections",
				},
			},
		},
	}), func(c *fiber.Ctx) error {
		// Dapatkan role yang matched
		matchedRoles := keycloakauth.GetMatchedRoles(c)

		// Siapkan response
		response := fiber.Map{
			"username":      c.Locals("preferred_username"),
			"email":         c.Locals("email"),
			"matched_roles": matchedRoles,
		}

		// Tambahkan atribut spesifik role jika ada
		// Admin
		if adminLevel := c.Locals("admin_level"); adminLevel != nil {
			response["admin_level"] = adminLevel
		}
		if adminPerms := c.Locals("admin_permissions"); adminPerms != nil {
			response["admin_permissions"] = adminPerms
		}
		if securityClearance := c.Locals("security_clearance"); securityClearance != nil {
			response["security_clearance"] = securityClearance
		}

		// User
		if userType := c.Locals("user_type"); userType != nil {
			response["user_type"] = userType
		}
		if subLevel := c.Locals("subscription_level"); subLevel != nil {
			response["subscription_level"] = subLevel
		}

		// Editor
		if contentAreas := c.Locals("content_areas"); contentAreas != nil {
			response["content_areas"] = contentAreas
		}
		if allowedSections := c.Locals("allowed_sections"); allowedSections != nil {
			response["allowed_sections"] = allowedSections
		}

		return c.JSON(response)
	})

	// Mulai server
	log.Fatal(app.Listen(":3001"))
}
