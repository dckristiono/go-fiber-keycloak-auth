# Go Fiber Keycloak Auth

[![Go Report Card](https://goreportcard.com/badge/github.com/dckristiono/go-fiber-keycloak-auth)](https://goreportcard.com/report/github.com/dckristiono/go-fiber-keycloak-auth)
[![GoDoc](https://godoc.org/github.com/dckristiono/go-fiber-keycloak-auth?status.svg)](https://godoc.org/github.com/dckristiono/go-fiber-keycloak-auth)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Modul autentikasi dan otorisasi Keycloak yang fleksibel untuk [GoFiber](https://gofiber.io/). Modul ini menyediakan cara sederhana dan kuat untuk mengintegrasikan Keycloak dengan aplikasi GoFiber.

## Fitur Utama

- 🔒 **Validasi Token**: Memvalidasi JWT token dari Keycloak menggunakan endpoint JWKS
- 🛡️ **Role-Based Access Control**: Melindungi route berdasarkan peran Keycloak (realm dan client roles)
- 🧩 **Middleware Terpadu**: Satu middleware untuk semua kebutuhan autentikasi dan otorisasi
- 🧪 **Testing-Friendly**: Didisain untuk memudahkan pengujian, termasuk mock clients
- 🚀 **Performa Optimal**: Caching JWKS untuk meningkatkan performa
- 🔄 **Attribute Mapping**: Memetakan atribut token Keycloak ke context Fiber
- 📝 **Role-Based Attribute Mapping**: Memetakan atribut berbeda untuk peran yang berbeda

## Instalasi

```bash
go get github.com/dckristiono/go-fiber-keycloak-auth
```

## Penggunaan Dasar

```go
package main

import (
    "github.com/gofiber/fiber/v2"
    "github.com/dckristiono/go-fiber-keycloak-auth"
)

func main() {
    app := fiber.New()
    
    // Konfigurasi Keycloak
    keycloakConfig := keycloakauth.Config{
        Realm:     "your-realm",
        ServerURL: "https://your-keycloak-server/auth",
        ClientID:  "your-client-id",
        CacheJWKS: true,
    }
    
    // Buat instance KeycloakAuth
    auth := keycloakauth.New(keycloakConfig)
    
    // Route publik
    app.Get("/", func(c *fiber.Ctx) error {
        return c.SendString("Halaman Publik")
    })
    
    // Route terproteksi
    app.Get("/profile", auth.Auth(keycloakauth.AuthOptions{
        Required: true,
    }), func(c *fiber.Ctx) error {
        user, _ := keycloakauth.GetUser(c)
        return c.JSON(fiber.Map{
            "message": "Profil Pengguna",
            "username": user.PreferredUsername,
        })
    })
    
    app.Listen(":3000")
}
```

## Unified Auth Middleware

Modul ini menggunakan pendekatan API yang bersih dengan menyediakan satu middleware utama untuk semua kebutuhan autentikasi:

```go
// Opsi konfigurasi Auth
type AuthOptions struct {
    Required          bool                   // Apakah autentikasi diharuskan (default: true)
    Roles             []string               // Role yang diperlukan (jika ada)
    AttributeMappings []string               // Attribute yang perlu di-map (jika ada)
    RoleMappings      []RoleAttributeMapping // Role-based attribute mappings (jika ada)
}

// RoleAttributeMapping untuk attribute berdasarkan role
type RoleAttributeMapping struct {
    Role               string   // Nama role
    AttributeMappings  []string // Atribut yang di-map untuk role ini
}
```

## Contoh Penggunaan

### 1. Route Publik
```go
app.Get("/public", func(c *fiber.Ctx) error {
    return c.SendString("Public route")
})
```

### 2. Autentikasi Sederhana
```go
app.Get("/profile", auth.Auth(keycloakauth.AuthOptions{
    Required: true,
}), func(c *fiber.Ctx) error {
    user, _ := keycloakauth.GetUser(c)
    return c.JSON(fiber.Map{
        "message": "Profil Pengguna",
        "username": user.PreferredUsername,
    })
})
```

### 3. Role-Based Authorization
```go
app.Get("/admin", auth.Auth(keycloakauth.AuthOptions{
    Required: true,
    Roles: []string{"admin", "super-admin"},
}), func(c *fiber.Ctx) error {
    user, _ := keycloakauth.GetUser(c)
    return c.JSON(fiber.Map{
        "message": "Halaman Admin",
        "username": user.PreferredUsername,
    })
})
```

### 4. Autentikasi Opsional
```go
app.Get("/dashboard", auth.Auth(keycloakauth.AuthOptions{
    Required: false,
}), func(c *fiber.Ctx) error {
    if !keycloakauth.IsAuthenticated(c) {
        return c.SendString("Dashboard Publik - Silakan login untuk fitur tambahan")
    }
    
    user, _ := keycloakauth.GetUser(c)
    return c.JSON(fiber.Map{
        "message": "Dashboard Pengguna",
        "username": user.PreferredUsername,
    })
})
```

### 5. Attribute Mapping
```go
app.Get("/user-details", auth.Auth(keycloakauth.AuthOptions{
    Required: true,
    AttributeMappings: []string{
        "preferred_username",
        "email",
        "attributes.organization",
        "attributes.jobs.name",
    },
}), func(c *fiber.Ctx) error {
    return c.JSON(fiber.Map{
        "username": c.Locals("preferred_username"),
        "email": c.Locals("email"),
        "organization": c.Locals("organization"),
        "job": c.Locals("name"), // Last part of attributes.jobs.name
    })
})
```

### 6. Role-Based Attribute Mapping
```go
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
        "username": c.Locals("preferred_username"),
        "matched_roles": matchedRoles,
    }
    
    // Tambahkan atribut khusus role jika tersedia
    if adminLevel := c.Locals("admin_level"); adminLevel != nil {
        response["admin_level"] = adminLevel
    }
    
    if subscription := c.Locals("subscription"); subscription != nil {
        response["subscription"] = subscription
    }
    
    return c.JSON(response)
})
```

### 7. Kombinasi Semua Fitur
```go
app.Get("/complex", auth.Auth(keycloakauth.AuthOptions{
    Required: false,              // Autentikasi opsional
    Roles:    []string{"premium"}, // Cek role ini
    AttributeMappings: []string{  // Attribute umum
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
}), handler)
```

## Helper Functions

Modul ini menyediakan beberapa fungsi helper untuk mengakses informasi dari token:

```go
// Get user information
user, ok := keycloakauth.GetUser(c)
if ok {
    fmt.Println(user.PreferredUsername, user.Email)
}

// Check if user is authenticated
if keycloakauth.IsAuthenticated(c) {
    // User is authenticated
}

// Check if user has required roles
if keycloakauth.HasRequiredRoles(c) {
    // User has required roles
}

// Check if user has a specific role
if keycloakauth.HasRole(c, "admin") {
    // Admin-specific code
}

// Check if user has a specific client role
if keycloakauth.HasClientRole(c, "my-client", "manager") {
    // Manager-specific code
}

// Get a specific attribute value
organization, ok := keycloakauth.GetAttributeValue(c, "attributes.organization")
if ok {
    fmt.Println("Organization:", organization)
}

// Get matched roles (for role-based attribute mapping)
matchedRoles := keycloakauth.GetMatchedRoles(c)
```

## Struktur Project

Struktur project dirancang agar modular dan mudah diuji:

```
go-fiber-keycloak-auth/
├── types.go                 # Definisi tipe data (Config, Claims, AuthOptions, dll)
├── auth.go                  # Implementasi utama KeycloakAuth (validasi token)
├── middleware.go            # Middleware Auth
├── helpers.go               # Fungsi bantuan untuk handler routes
│
├── examples/                # Contoh aplikasi
│   ├── basic/               # Contoh dasar
│   ├── advanced/            # Contoh lanjutan (attribute mapping)
│   └── unified/             # Contoh middleware unified Auth
```

## Pengujian

Modul ini dilengkapi dengan test yang komprehensif. Untuk menjalankan semua test:

```bash
go test -v ./...
```

Untuk menjalankan test dengan code coverage:

```bash
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

## Contoh

Periksa folder [examples](./examples) untuk contoh penggunaan lengkap.

## Lisensi

Modul ini tersedia di bawah lisensi MIT. Lihat file [LICENSE](./LICENSE) untuk detail lengkap.