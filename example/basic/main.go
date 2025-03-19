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
		Realm:     "my-realm",                   // Sesuaikan dengan realm Keycloak Anda
		ServerURL: "http://localhost:8080/auth", // Sesuaikan dengan URL server Keycloak Anda
		ClientID:  "my-client",                  // Sesuaikan dengan client ID Anda
		CacheJWKS: true,
	}

	// Buat instance KeycloakAuth
	auth := keycloakauth.New(keycloakConfig)

	// -------------------------------
	// CONTOH ROUTE DASAR (menggunakan Auth terpadu)
	// -------------------------------

	// 1. Route Publik (Tidak memerlukan autentikasi)
	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("Halaman Publik - Dapat diakses siapa saja")
	})

	// 2. Route dengan Autentikasi Wajib
	// Lama: auth.Protect()
	// Baru: auth.Auth({Required: true})
	app.Get("/profile", auth.Auth(keycloakauth.AuthOptions{
		Required: true,
	}), func(c *fiber.Ctx) error {
		user, _ := keycloakauth.GetUser(c)
		return c.JSON(fiber.Map{
			"message":  "Profil Pengguna",
			"username": user.PreferredUsername,
			"email":    user.Email,
		})
	})

	// 3. Route dengan Role Tunggal
	// Lama: auth.ProtectWithRole("admin")
	// Baru: auth.Auth({Required: true, Roles: []string{"admin"}})
	app.Get("/admin", auth.Auth(keycloakauth.AuthOptions{
		Required: true,
		Roles:    []string{"admin"},
	}), func(c *fiber.Ctx) error {
		user, _ := keycloakauth.GetUser(c)
		return c.JSON(fiber.Map{
			"message":  "Halaman Admin",
			"username": user.PreferredUsername,
		})
	})

	// 4. Route dengan Multiple Roles (salah satu role harus dimiliki)
	// Lama: auth.ProtectWithRoles([]string{"editor", "admin", "content-manager"})
	// Baru: auth.Auth({Required: true, Roles: []string{"editor", "admin", "content-manager"}})
	app.Get("/content", auth.Auth(keycloakauth.AuthOptions{
		Required: true,
		Roles:    []string{"editor", "admin", "content-manager"},
	}), func(c *fiber.Ctx) error {
		user, _ := keycloakauth.GetUser(c)
		return c.JSON(fiber.Map{
			"message":  "Manajemen Konten",
			"username": user.PreferredUsername,
		})
	})

	// 5. Route Publik dengan Auth Opsional
	// Lama: auth.OptionalAuthWithRoles([]string{"user", "admin"})
	// Baru: auth.Auth({Required: false, Roles: []string{"user", "admin"}})
	app.Get("/dashboard", auth.Auth(keycloakauth.AuthOptions{
		Required: false,
		Roles:    []string{"user", "admin"},
	}), func(c *fiber.Ctx) error {
		if !keycloakauth.IsAuthenticated(c) {
			return c.SendString("Dashboard Publik - Silakan login untuk fitur tambahan")
		}

		user, _ := keycloakauth.GetUser(c)

		if keycloakauth.HasRequiredRoles(c) {
			return c.JSON(fiber.Map{
				"message":  "Dashboard Pengguna Terautentikasi dengan Role yang Sesuai",
				"username": user.PreferredUsername,
				"email":    user.Email,
			})
		}

		return c.JSON(fiber.Map{
			"message":  "Dashboard Pengguna Terautentikasi tanpa Role yang Sesuai",
			"username": user.PreferredUsername,
		})
	})

	// Mulai server
	log.Fatal(app.Listen(":3000"))
}
