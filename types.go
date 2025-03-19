package keycloakauth

import (
	"github.com/golang-jwt/jwt/v5"
	"net/http"
	"time"
)

// Config represents the Keycloak connection configuration
type Config struct {
	Realm         string
	ServerURL     string
	ClientID      string
	ClientSecret  string // Optional: Hanya diperlukan untuk client credentials flow atau resource owner flow
	PublicKeyURL  string // Optional, will be constructed from ServerURL and Realm if empty
	CacheJWKS     bool   // Whether to cache the JWKS (public keys)
	CacheDuration time.Duration
}

// KeycloakClaims extends the standard JWT claims with Keycloak specific claims
type KeycloakClaims struct {
	jwt.RegisteredClaims
	RealmAccess struct {
		Roles []string `json:"roles"`
	} `json:"realm_access"`
	ResourceAccess map[string]struct {
		Roles []string `json:"roles"`
	} `json:"resource_access"`
	PreferredUsername string                 `json:"preferred_username"`
	GivenName         string                 `json:"given_name"`
	FamilyName        string                 `json:"family_name"`
	Email             string                 `json:"email"`
	EmailVerified     bool                   `json:"email_verified"`
	Attributes        map[string]interface{} `json:"attributes,omitempty"`
	OtherClaims       map[string]interface{} `json:"-"`
}

// JWKS represents a JSON Web Key Set
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a JSON Web Key
type JWK struct {
	Kid string   `json:"kid"`
	Kty string   `json:"kty"`
	Alg string   `json:"alg"`
	Use string   `json:"use"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c"`
}

// AuthOptions mendefinisikan opsi untuk middleware Auth
type AuthOptions struct {
	Required          bool                   // Apakah autentikasi diharuskan (default: true)
	Roles             []string               // Role yang diperlukan (jika ada)
	AttributeMappings []string               // Attribute yang perlu di-map (jika ada)
	RoleMappings      []RoleAttributeMapping // Role-based attribute mappings (jika ada)
}

// RoleAttributeMapping defines attribute mappings for a specific role
type RoleAttributeMapping struct {
	Role              string   // Role name
	AttributeMappings []string // Attributes to map for this role
}

// HTTPClient adalah interface untuk HTTP client yang dapat diganti untuk tujuan pengujian
type HTTPClient interface {
	Get(url string) (*http.Response, error)
}
