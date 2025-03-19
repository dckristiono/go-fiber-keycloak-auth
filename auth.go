package keycloakauth

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// KeycloakAuth handles Keycloak authentication
type KeycloakAuth struct {
	config      Config
	jwksCache   *JWKS
	lastUpdated time.Time
	httpClient  HTTPClient // Interface instead of concrete *http.Client
}

// New creates a new KeycloakAuth instance
func New(config Config) *KeycloakAuth {
	// Pastikan URL dan Realm telah diisi
	if config.ServerURL == "" || config.Realm == "" {
		panic("ServerURL dan Realm harus diisi")
	}

	// ClientID harus diisi untuk pemeriksaan peran client
	if config.ClientID == "" {
		panic("ClientID harus diisi")
	}

	// ClientSecret bersifat opsional

	// Buat URL publik key jika tidak disediakan
	if config.PublicKeyURL == "" {
		config.PublicKeyURL = fmt.Sprintf("%s/realms/%s/protocol/openid-connect/certs", config.ServerURL, config.Realm)
	}

	if config.CacheDuration == 0 {
		config.CacheDuration = 1 * time.Hour
	}

	return &KeycloakAuth{
		config:     config,
		httpClient: &http.Client{}, // Default HTTP client
	}
}

// SetHTTPClient sets a custom HTTP client (useful for testing)
func (k *KeycloakAuth) SetHTTPClient(client HTTPClient) {
	k.httpClient = client
}

// getJWKS fetches the JSON Web Key Set from Keycloak
func (k *KeycloakAuth) getJWKS() (*JWKS, error) {
	// Return cached JWKS if available and not expired
	if k.config.CacheJWKS && k.jwksCache != nil && time.Since(k.lastUpdated) < k.config.CacheDuration {
		return k.jwksCache, nil
	}

	// Fetch JWKS from Keycloak
	resp, err := k.httpClient.Get(k.config.PublicKeyURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch JWKS: status code %d", resp.StatusCode)
	}

	var jwks JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("failed to decode JWKS: %w", err)
	}

	// Cache JWKS
	if k.config.CacheJWKS {
		k.jwksCache = &jwks
		k.lastUpdated = time.Now()
	}

	return &jwks, nil
}

// findJWK finds the JWK that matches the kid in the token header
func (k *KeycloakAuth) findJWK(token *jwt.Token) (*JWK, error) {
	jwks, err := k.getJWKS()
	if err != nil {
		return nil, err
	}

	kid, ok := token.Header["kid"].(string)
	if !ok {
		return nil, errors.New("token header missing kid")
	}

	for _, key := range jwks.Keys {
		if key.Kid == kid {
			return &key, nil
		}
	}

	return nil, errors.New("unable to find matching JWK for kid")
}

// jwkToPublicKey converts a JWK to an RSA public key
func jwkToPublicKey(jwk *JWK) (*rsa.PublicKey, error) {
	// Decode the modulus and exponent
	n, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode modulus: %w", err)
	}

	e, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode exponent: %w", err)
	}

	// Convert to big.Int
	modulus := new(big.Int).SetBytes(n)

	// Convert exponent bytes to int
	var exponent int
	for i := 0; i < len(e); i++ {
		exponent = exponent<<8 + int(e[i])
	}

	// Create RSA public key
	return &rsa.PublicKey{
		N: modulus,
		E: exponent,
	}, nil
}

// extractTokenFromHeader extracts the JWT token from Authorization header
// private function, tidak diekspos ke luar package
func extractTokenFromHeader(c interface{}) (string, error) {
	var authHeader string

	// Check the type of the context and extract the Authorization header
	switch ctx := c.(type) {
	case interface{ Get(string) string }:
		authHeader = ctx.Get("Authorization")
	default:
		return "", errors.New("unsupported context type")
	}

	if authHeader == "" {
		return "", errors.New("missing authorization header")
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return "", errors.New("invalid authorization header format")
	}

	return parts[1], nil
}

// validateToken validates the JWT token
func (k *KeycloakAuth) validateToken(tokenString string) (*KeycloakClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &KeycloakClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Ensure the token uses the correct signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Get the JWK for this token
		jwk, err := k.findJWK(token)
		if err != nil {
			return nil, err
		}

		// Convert JWK to public key
		return jwkToPublicKey(jwk)
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*KeycloakClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}

	// Capture any unmapped claims into OtherClaims map
	if mapClaims, ok := token.Claims.(jwt.MapClaims); ok {
		claims.OtherClaims = make(map[string]interface{})
		for k, v := range mapClaims {
			if k != "realm_access" && k != "resource_access" &&
				k != "preferred_username" && k != "given_name" &&
				k != "family_name" && k != "email" && k != "email_verified" &&
				k != "exp" && k != "iat" && k != "auth_time" &&
				k != "jti" && k != "iss" && k != "aud" &&
				k != "sub" && k != "typ" && k != "azp" &&
				k != "session_state" && k != "acr" && k != "sid" &&
				k != "attributes" {
				claims.OtherClaims[k] = v
			}
		}
	}

	return claims, nil
}
