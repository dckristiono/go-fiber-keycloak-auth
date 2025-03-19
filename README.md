# Go Fiber Keycloak Auth

## Perubahan API

Modul ini telah disederhanakan dengan menyediakan **satu middleware utama** untuk autentikasi dan otorisasi Keycloak:

### Unified Auth Middleware

```go
// Contoh penggunaan Auth middleware
app.Get("/user-info", auth.Auth(keycloakauth.AuthOptions{
    Required: true,              // Wajib autentikasi
    Roles: []string{"user"},     // Peran yang diperlukan
    AttributeMappings: []string{ // Atribut yang perlu di-map
        "preferred_username",
        "email",
        "attributes.organization",
    },
}), handler)
```

Middleware `Auth()` adalah satu-satunya middleware terpadu yang dibutuhkan untuk semua kebutuhan autentikasi dan otorisasi.

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
}), handler)
```

### 3. Role-Based Authorization
```go
app.Get("/admin", auth.Auth(keycloakauth.AuthOptions{
    Required: true,
    Roles: []string{"admin", "super-admin"},
}), handler)
```

### 4. Autentikasi Opsional
```go
app.Get("/dashboard", auth.Auth(keycloakauth.AuthOptions{
    Required: false,
}), handler)
```

### 5. Attribute Mapping
```go
app.Get("/user-details", auth.Auth(keycloakauth.AuthOptions{
    Required: true,
    AttributeMappings: []string{
        "preferred_username",
        "email",
        "attributes.organization",
    },
}), handler)
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
}), handler)
```

## Helper Functions

Fungsi helper tetap tersedia untuk mengakses informasi dari token:

```go
// Get user information
user, ok := keycloakauth.GetUser(c)

// Check if user is authenticated
if keycloakauth.IsAuthenticated(c) {
    // User is authenticated
}

// Check if user has required roles
if keycloakauth.HasRequiredRoles(c) {
    // User has required roles
}

// Check specific roles
if keycloakauth.HasRole(c, "admin") {
    // User has admin role
}

// Get attribute values
organization, ok := keycloakauth.GetAttributeValue(c, "attributes.organization")

// Get matched roles
matchedRoles := keycloakauth.GetMatchedRoles(c)
```