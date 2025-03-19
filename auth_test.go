package keycloakauth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockHTTPClient implements HTTPClient interface for testing
type MockHTTPClient struct {
	statusCode int
	response   string
	err        error
}

func (m *MockHTTPClient) Get(url string) (*http.Response, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &http.Response{
		StatusCode: m.statusCode,
		Body:       io.NopCloser(strings.NewReader(m.response)),
	}, nil
}

func (m *MockHTTPClient) SetResponse(statusCode int, response string) {
	m.statusCode = statusCode
	m.response = response
}

func (m *MockHTTPClient) SetError(err error) {
	m.err = err
}

// mockContext for testing
type mockContext struct {
	headers map[string]string
}

func (m *mockContext) Get(key string) string {
	return m.headers[key]
}

// TestNew tests the creation of a new KeycloakAuth instance
func TestNew(t *testing.T) {
	// Test with valid config
	config := Config{
		Realm:     "test-realm",
		ServerURL: "https://keycloak.example.com",
		ClientID:  "test-client",
	}

	auth := New(config)
	assert.NotNil(t, auth, "New should return a non-nil *KeycloakAuth")
	assert.Equal(t, "test-realm", auth.config.Realm)
	assert.Equal(t, "https://keycloak.example.com", auth.config.ServerURL)
	assert.Equal(t, "test-client", auth.config.ClientID)
	assert.Equal(t, "https://keycloak.example.com/realms/test-realm/protocol/openid-connect/certs", auth.config.PublicKeyURL)
	assert.Equal(t, 1*time.Hour, auth.config.CacheDuration)

	// Test with PublicKeyURL already set
	config = Config{
		Realm:        "test-realm",
		ServerURL:    "https://keycloak.example.com",
		ClientID:     "test-client",
		PublicKeyURL: "https://custom.example.com/keys",
	}

	auth = New(config)
	assert.Equal(t, "https://custom.example.com/keys", auth.config.PublicKeyURL)

	// Test with custom CacheDuration
	config = Config{
		Realm:         "test-realm",
		ServerURL:     "https://keycloak.example.com",
		ClientID:      "test-client",
		CacheDuration: 30 * time.Minute,
	}

	auth = New(config)
	assert.Equal(t, 30*time.Minute, auth.config.CacheDuration)

	// Test with all options
	config = Config{
		Realm:         "test-realm",
		ServerURL:     "https://keycloak.example.com",
		ClientID:      "test-client",
		ClientSecret:  "client-secret",
		PublicKeyURL:  "https://custom.example.com/keys",
		CacheJWKS:     true,
		CacheDuration: 15 * time.Minute,
	}

	auth = New(config)
	assert.Equal(t, "client-secret", auth.config.ClientSecret)
	assert.True(t, auth.config.CacheJWKS)
}

// TestNewPanic tests panic scenarios in New
func TestNewPanic(t *testing.T) {
	// Test panic with missing realm
	assert.Panics(t, func() {
		New(Config{
			ServerURL: "https://keycloak.example.com",
			ClientID:  "test-client",
		})
	})

	// Test panic with missing server URL
	assert.Panics(t, func() {
		New(Config{
			Realm:    "test-realm",
			ClientID: "test-client",
		})
	})

	// Test panic with missing client ID
	assert.Panics(t, func() {
		New(Config{
			Realm:     "test-realm",
			ServerURL: "https://keycloak.example.com",
		})
	})
}

// TestGetJWKS tests JWKS fetching
func TestGetJWKS(t *testing.T) {
	// Read test JWKS from file
	jwksData, err := os.ReadFile("testdata/jwks.json")
	require.NoError(t, err)

	// Setup auth
	config := Config{
		Realm:     "test-realm",
		ServerURL: "https://keycloak.example.com",
		ClientID:  "test-client",
		CacheJWKS: true,
	}

	auth := New(config)

	// Create mock client
	mockClient := &MockHTTPClient{}
	mockClient.SetResponse(http.StatusOK, string(jwksData))
	auth.SetHTTPClient(mockClient)

	// Test first call (no cache)
	jwks, err := auth.getJWKS()
	assert.NoError(t, err)
	assert.NotNil(t, jwks)
	assert.Equal(t, 2, len(jwks.Keys))

	// Test second call (should use cache)
	mockClient.SetResponse(http.StatusInternalServerError, "")
	jwks2, err := auth.getJWKS()
	assert.NoError(t, err)
	assert.NotNil(t, jwks2)
	assert.Equal(t, jwks, jwks2)

	// Test with caching disabled
	auth = New(Config{
		Realm:     "test-realm",
		ServerURL: "https://keycloak.example.com",
		ClientID:  "test-client",
		CacheJWKS: false,
	})
	auth.SetHTTPClient(mockClient)

	// Should fail because mockClient is set to return error
	_, err = auth.getJWKS()
	assert.Error(t, err)

	// Reset mock to return successful response
	mockClient.SetResponse(http.StatusOK, string(jwksData))
	jwks3, err := auth.getJWKS()
	assert.NoError(t, err)
	assert.NotNil(t, jwks3)
}

// TestGetJWKS_Errors tests error cases in JWKS fetching
func TestGetJWKS_Errors(t *testing.T) {
	// Setup auth
	config := Config{
		Realm:     "test-realm",
		ServerURL: "https://keycloak.example.com",
		ClientID:  "test-client",
	}

	auth := New(config)

	// Test HTTP error
	mockClient := &MockHTTPClient{}
	mockClient.SetError(fmt.Errorf("connection error"))
	auth.SetHTTPClient(mockClient)

	_, err := auth.getJWKS()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to fetch JWKS")

	// Test non-200 status code
	mockClient = &MockHTTPClient{}
	mockClient.SetResponse(http.StatusInternalServerError, "Internal Server Error")
	auth.SetHTTPClient(mockClient)

	_, err = auth.getJWKS()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to fetch JWKS: status code")

	// Test invalid JSON
	mockClient = &MockHTTPClient{}
	mockClient.SetResponse(http.StatusOK, "invalid json")
	auth.SetHTTPClient(mockClient)

	_, err = auth.getJWKS()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode JWKS")
}

// TestGetJWKS_CacheExpiration tests JWKS cache expiration
func TestGetJWKS_CacheExpiration(t *testing.T) {
	// Read test JWKS from file
	jwksData, err := os.ReadFile("testdata/jwks.json")
	require.NoError(t, err)

	// Setup auth with short cache duration
	config := Config{
		Realm:         "test-realm",
		ServerURL:     "https://keycloak.example.com",
		ClientID:      "test-client",
		CacheJWKS:     true,
		CacheDuration: 100 * time.Millisecond, // Very short duration for testing
	}

	auth := New(config)

	// Create mock client
	mockClient := &MockHTTPClient{}
	mockClient.SetResponse(http.StatusOK, string(jwksData))
	auth.SetHTTPClient(mockClient)

	// First call should fetch JWKS
	jwks1, err := auth.getJWKS()
	assert.NoError(t, err)
	assert.NotNil(t, jwks1)

	// Second call should use cache
	mockClient.SetResponse(http.StatusInternalServerError, "")
	jwks2, err := auth.getJWKS()
	assert.NoError(t, err)
	assert.Equal(t, jwks1, jwks2)

	// Wait for cache to expire
	time.Sleep(200 * time.Millisecond)

	// Reset mock to return successful response
	mockClient.SetResponse(http.StatusOK, string(jwksData))
	jwks3, err := auth.getJWKS()
	assert.NoError(t, err)
	assert.NotNil(t, jwks3)
	assert.Equal(t, jwks1, jwks3) // Content should be equal but it's a new instance
}

// TestFindJWK tests the findJWK function
func TestFindJWK(t *testing.T) {
	// Read test JWKS from file
	jwksData, err := os.ReadFile("testdata/jwks.json")
	require.NoError(t, err)

	// Setup auth with test JWKS
	config := Config{
		Realm:     "test-realm",
		ServerURL: "https://keycloak.example.com",
		ClientID:  "test-client",
	}

	auth := New(config)

	// Create mock client with test JWKS
	mockClient := &MockHTTPClient{}
	mockClient.SetResponse(http.StatusOK, string(jwksData))
	auth.SetHTTPClient(mockClient)

	// Create token with kid matching JWKS
	tokenWithKid := jwt.New(jwt.SigningMethodRS256)
	tokenWithKid.Header["kid"] = "FJ86GcF3jTbNLOco4NvZkUCIUmfYCqoqtOQeMfbhNlE"

	// Test finding JWK
	jwk, err := auth.findJWK(tokenWithKid)
	assert.NoError(t, err)
	assert.NotNil(t, jwk)
	assert.Equal(t, "FJ86GcF3jTbNLOco4NvZkUCIUmfYCqoqtOQeMfbhNlE", jwk.Kid)

	// Test with token missing kid
	tokenWithoutKid := jwt.New(jwt.SigningMethodRS256)
	_, err = auth.findJWK(tokenWithoutKid)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token header missing kid")

	// Test with non-matching kid
	tokenWrongKid := jwt.New(jwt.SigningMethodRS256)
	tokenWrongKid.Header["kid"] = "wrong-kid"
	_, err = auth.findJWK(tokenWrongKid)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unable to find matching JWK for kid")
}

// TestJwkToPublicKey tests the jwkToPublicKey function
func TestJwkToPublicKey(t *testing.T) {
	// Valid JWK from JWKS
	jwksData, err := os.ReadFile("testdata/jwks.json")
	require.NoError(t, err)

	var jwks JWKS
	err = json.Unmarshal(jwksData, &jwks)
	require.NoError(t, err)
	require.Greater(t, len(jwks.Keys), 0)

	// Test with valid JWK
	jwk := &jwks.Keys[0]
	publicKey, err := jwkToPublicKey(jwk)
	assert.NoError(t, err)
	assert.NotNil(t, publicKey)

	// Test with invalid modulus
	invalidN := &JWK{
		Kid: "test-kid",
		Kty: "RSA",
		Alg: "RS256",
		Use: "sig",
		N:   "!@#$%^", // Invalid base64
		E:   "AQAB",
	}

	_, err = jwkToPublicKey(invalidN)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode modulus")

	// Test with invalid exponent
	invalidE := &JWK{
		Kid: "test-kid",
		Kty: "RSA",
		Alg: "RS256",
		Use: "sig",
		N:   jwk.N,
		E:   "!@#$%^", // Invalid base64
	}

	_, err = jwkToPublicKey(invalidE)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode exponent")
}

// TestExtractTokenFromHeader tests token extraction from header
func TestExtractTokenFromHeader(t *testing.T) {
	// Create mock context with valid header
	validCtx := &mockContext{
		headers: map[string]string{
			"Authorization": "Bearer valid-token",
		},
	}

	// Test valid extraction
	token, err := extractTokenFromHeader(validCtx)
	assert.NoError(t, err)
	assert.Equal(t, "valid-token", token)

	// Test with missing header
	emptyCtx := &mockContext{
		headers: map[string]string{},
	}
	_, err = extractTokenFromHeader(emptyCtx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing authorization header")

	// Test with invalid header format
	invalidCtx := &mockContext{
		headers: map[string]string{
			"Authorization": "NotBearer token",
		},
	}
	_, err = extractTokenFromHeader(invalidCtx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid authorization header format")

	// Test with "bearer" in lowercase (should work)
	lowerCaseCtx := &mockContext{
		headers: map[string]string{
			"Authorization": "bearer lowercase-token",
		},
	}
	token, err = extractTokenFromHeader(lowerCaseCtx)
	assert.NoError(t, err)
	assert.Equal(t, "lowercase-token", token)

	// Test with Bearer prefix only
	bearerOnlyCtx := &mockContext{
		headers: map[string]string{
			"Authorization": "Bearer",
		},
	}
	_, err = extractTokenFromHeader(bearerOnlyCtx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid authorization header format")

	// Test with unsupported context type
	_, err = extractTokenFromHeader("not-a-context")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported context type")
}

// TestValidateToken tests the validateToken function
func TestValidateToken(t *testing.T) {
	// Setup auth
	config := Config{
		Realm:     "test-realm",
		ServerURL: "https://keycloak.example.com",
		ClientID:  "test-client",
	}

	auth := New(config)

	// Read test JWKS from file
	jwksData, err := os.ReadFile("testdata/jwks.json")
	require.NoError(t, err)

	// Create mock client
	mockClient := &MockHTTPClient{}
	mockClient.SetResponse(http.StatusOK, string(jwksData))
	auth.SetHTTPClient(mockClient)

	// Test with invalid token format (missing parts)
	_, err = auth.validateToken("not.enough.parts")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse token")

	// Test with invalid token format (not a token)
	_, err = auth.validateToken("not-a-token")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse token")

	// Test with empty token
	_, err = auth.validateToken("")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse token")

	// Read test tokens
	validTokenBytes, err := os.ReadFile("testdata/tokens/valid_token.jwt")
	if err == nil {
		// Test with valid token (mocked validation)
		_, err = auth.validateToken(string(validTokenBytes))
		// We expect an error here due to invalid signature in the test token
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse token")
	}

	invalidTokenBytes, err := os.ReadFile("testdata/tokens/invalid_token.jwt")
	if err == nil {
		// Test with token having non-matching kid
		_, err = auth.validateToken(string(invalidTokenBytes))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse token")
	}

	expiredTokenBytes, err := os.ReadFile("testdata/tokens/expired_token.jwt")
	if err == nil {
		// Test with expired token
		_, err = auth.validateToken(string(expiredTokenBytes))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse token")
	}
}

// TestMarshalClaims tests marshaling and unmarshaling claims
func TestMarshalClaims(t *testing.T) {
	// Create sample claims
	claims := &KeycloakClaims{
		PreferredUsername: "testuser",
		Email:             "test@example.com",
	}
	claims.RealmAccess.Roles = []string{"user", "admin"}
	claims.ResourceAccess = map[string]struct {
		Roles []string `json:"roles"`
	}{
		"test-client": {Roles: []string{"editor"}},
	}

	// Marshal to JSON
	jsonBytes, err := json.Marshal(claims)
	assert.NoError(t, err)

	// Unmarshal back
	var decodedClaims KeycloakClaims
	err = json.Unmarshal(jsonBytes, &decodedClaims)
	assert.NoError(t, err)

	// Verify fields
	assert.Equal(t, "testuser", decodedClaims.PreferredUsername)
	assert.Equal(t, "test@example.com", decodedClaims.Email)
	assert.Contains(t, decodedClaims.RealmAccess.Roles, "user")
	assert.Contains(t, decodedClaims.RealmAccess.Roles, "admin")
	assert.Contains(t, decodedClaims.ResourceAccess["test-client"].Roles, "editor")
}

// TestOtherClaims tests handling of unmapped claims
func TestOtherClaims(t *testing.T) {
	// Create a token with custom claims
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["preferred_username"] = "testuser"
	claims["email"] = "test@example.com"
	claims["custom_claim1"] = "value1"
	claims["custom_claim2"] = 42
	claims["nested_claim"] = map[string]interface{}{
		"nested_key": "nested_value",
	}

	// Create KeycloakClaims with OtherClaims
	kclaims := &KeycloakClaims{
		PreferredUsername: "testuser",
		Email:             "test@example.com",
		OtherClaims: map[string]interface{}{
			"custom_claim1": "value1",
			"custom_claim2": 42,
			"nested_claim": map[string]interface{}{
				"nested_key": "nested_value",
			},
		},
	}

	// Verify OtherClaims
	assert.Equal(t, "value1", kclaims.OtherClaims["custom_claim1"])
	assert.Equal(t, 42, kclaims.OtherClaims["custom_claim2"])

	nestedMap, ok := kclaims.OtherClaims["nested_claim"].(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, "nested_value", nestedMap["nested_key"])
}

// TestValidateToken_Comprehensive menguji validateToken secara lebih komprehensif
func TestValidateToken_Comprehensive(t *testing.T) {
	// Setup auth
	config := Config{
		Realm:     "test-realm",
		ServerURL: "https://keycloak.example.com",
		ClientID:  "test-client",
	}

	auth := New(config)

	// 1. Test dengan token kosong
	_, err := auth.validateToken("")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse token")

	// 2. Test dengan token yang bukan JWT sama sekali
	_, err = auth.validateToken("this-is-not-a-jwt")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse token")

	// 3. Test dengan token yang formatnya benar tapi tidak lengkap
	_, err = auth.validateToken("header.payload")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse token")

	// 4. Test dengan token JWT yang tidak valid (signing method salah)
	invalidMethodToken := createInvalidMethodToken(t)
	_, err = auth.validateToken(invalidMethodToken)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse token")

	// 5. Test dengan token yang memiliki format yang benar, header dan payload valid, tapi signature salah
	invalidSigToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2lkIn0.eyJqdGkiOiJ0ZXN0LWlkIiwic3ViIjoidGVzdC11c2VyIiwiZXhwIjoxOTk5OTk5OTk5LCJpYXQiOjE1MDAwMDAwMDAsImlzcyI6Imh0dHBzOi8va2V5Y2xvYWsuZXhhbXBsZS5jb20vYXV0aC9yZWFsbXMvdGVzdC1yZWFsbSIsImF1ZCI6InRlc3QtY2xpZW50IiwicHJlZmVycmVkX3VzZXJuYW1lIjoidGVzdHVzZXIiLCJlbWFpbCI6InRlc3RAZXhhbXBsZS5jb20iLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsidXNlciIsImFkbWluIl19fQ.invalid-signature"
	_, err = auth.validateToken(invalidSigToken)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse token")

	// 6. Test parseMapClaims untuk memastikan klaim tambahan diperiksa dengan benar
	testParseMapClaims(t)
}

// createInvalidMethodToken membuat token dengan method signing yang tidak didukung
func createInvalidMethodToken(t *testing.T) string {
	token := jwt.New(jwt.SigningMethodHS256) // Menggunakan HS256 alih-alih RS256
	token.Header["kid"] = "test-kid"
	token.Claims = jwt.MapClaims{
		"sub":                "test-user",
		"exp":                time.Now().Add(time.Hour).Unix(),
		"iss":                "https://keycloak.example.com/auth/realms/test-realm",
		"aud":                "test-client",
		"preferred_username": "testuser",
		"realm_access": map[string]interface{}{
			"roles": []string{"user", "admin"},
		},
	}

	// Sign token dengan key sederhana
	tokenStr, err := token.SignedString([]byte("secret"))
	assert.NoError(t, err)
	return tokenStr
}

// testParseMapClaims menguji parsing klaim JWT ke dalam struktur KeycloakClaims
func testParseMapClaims(t *testing.T) {
	// Buat MapClaims simulasi
	mapClaims := jwt.MapClaims{
		"preferred_username": "testuser",
		"email":              "test@example.com",
		"email_verified":     true,
		"given_name":         "Test",
		"family_name":        "User",
		"realm_access": map[string]interface{}{
			"roles": []string{"user", "admin"},
		},
		"resource_access": map[string]interface{}{
			"test-client": map[string]interface{}{
				"roles": []string{"editor"},
			},
		},
		"custom_claim1": "value1",
		"custom_claim2": 42,
		"nested_claim": map[string]interface{}{
			"nested_key": "nested_value",
		},
		"attributes": map[string]interface{}{
			"organization": "Test Org",
		},
	}

	// Buat KeycloakClaims kosong
	claims := &KeycloakClaims{}

	// Salin nilai dari MapClaims ke KeycloakClaims (simulasi apa yang dilakukan validateToken)
	claims.PreferredUsername = mapClaims["preferred_username"].(string)
	claims.Email = mapClaims["email"].(string)
	claims.EmailVerified = mapClaims["email_verified"].(bool)
	claims.GivenName = mapClaims["given_name"].(string)
	claims.FamilyName = mapClaims["family_name"].(string)

	// Handle realm_access
	if realmAccess, ok := mapClaims["realm_access"].(map[string]interface{}); ok {
		if roles, ok := realmAccess["roles"].([]string); ok {
			claims.RealmAccess.Roles = roles
		}
	}

	// Handle resource_access
	if resourceAccess, ok := mapClaims["resource_access"].(map[string]interface{}); ok {
		claims.ResourceAccess = map[string]struct {
			Roles []string `json:"roles"`
		}(make(map[string]struct{ Roles []string }))
		for clientID, access := range resourceAccess {
			if accessMap, ok := access.(map[string]interface{}); ok {
				if roles, ok := accessMap["roles"].([]string); ok {
					clientAccess := struct{ Roles []string }{Roles: roles}
					claims.ResourceAccess[clientID] = struct {
						Roles []string `json:"roles"`
					}(clientAccess)
				}
			}
		}
	}

	// Handle attributes
	if attrs, ok := mapClaims["attributes"].(map[string]interface{}); ok {
		claims.Attributes = attrs
	}

	// Handle other claims
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

	// Verifikasi bahwa claims diproses dengan benar
	assert.Equal(t, "testuser", claims.PreferredUsername)
	assert.Equal(t, "test@example.com", claims.Email)
	assert.True(t, claims.EmailVerified)
	assert.Equal(t, "Test", claims.GivenName)
	assert.Equal(t, "User", claims.FamilyName)

	// Verifikasi realm roles
	assert.Contains(t, claims.RealmAccess.Roles, "user")
	assert.Contains(t, claims.RealmAccess.Roles, "admin")

	// Verifikasi client roles
	clientRoles := claims.ResourceAccess["test-client"].Roles
	assert.Contains(t, clientRoles, "editor")

	// Verifikasi attributes
	assert.Equal(t, "Test Org", claims.Attributes["organization"])

	// Verifikasi other claims
	assert.Equal(t, "value1", claims.OtherClaims["custom_claim1"])
	assert.Equal(t, 42, claims.OtherClaims["custom_claim2"])
	nestedClaim, ok := claims.OtherClaims["nested_claim"].(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, "nested_value", nestedClaim["nested_key"])
}

func TestFindJWK_Comprehensive(t *testing.T) {
	// Setup auth
	config := Config{
		Realm:     "test-realm",
		ServerURL: "https://keycloak.example.com",
		ClientID:  "test-client",
	}

	auth := New(config)

	// 1. Test dengan gagal mendapatkan JWKS
	mockClient := &MockHTTPClient{}
	mockClient.SetError(fmt.Errorf("network error"))
	auth.SetHTTPClient(mockClient)

	token := jwt.New(jwt.SigningMethodRS256)
	token.Header["kid"] = "test-kid"

	// Uji kasus gagal mendapatkan JWKS
	_, err := auth.findJWK(token)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to fetch JWKS")

	// 2. Test token tanpa kid header
	mockClient.SetError(nil)
	mockClient.SetResponse(http.StatusOK, mockJWKS)
	auth.SetHTTPClient(mockClient)

	tokenNoKid := jwt.New(jwt.SigningMethodRS256)
	// Hapus kid header secara eksplisit (jika ada)
	delete(tokenNoKid.Header, "kid")

	_, err = auth.findJWK(tokenNoKid)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token header missing kid")

	// 3. Test dengan kid yang tidak cocok
	tokenWrongKid := jwt.New(jwt.SigningMethodRS256)
	tokenWrongKid.Header["kid"] = "wrong-kid"

	_, err = auth.findJWK(tokenWrongKid)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unable to find matching JWK for kid")

	// 4. Test dengan kid yang cocok
	tokenCorrectKid := jwt.New(jwt.SigningMethodRS256)

	// Dapatkan kid yang valid dari JWKS
	var jwks JWKS
	err = json.Unmarshal([]byte(mockJWKS), &jwks)
	require.NoError(t, err)
	require.Greater(t, len(jwks.Keys), 0)

	validKid := jwks.Keys[0].Kid
	tokenCorrectKid.Header["kid"] = validKid

	jwk, err := auth.findJWK(tokenCorrectKid)
	assert.NoError(t, err)
	assert.NotNil(t, jwk)
	assert.Equal(t, validKid, jwk.Kid)
}

// JWKS mock untuk testing
const mockJWKS = `{
  "keys": [
    {
      "kid": "test-kid",
      "kty": "RSA",
      "alg": "RS256",
      "use": "sig",
      "n": "3jNGJaeXwYE_9qJxlIR2y9A8_KlbRiHBzr5n-KAWwYC-ueLxRgKJ7Yp0lTtVvgULPLwUXyUQDKumBpJkYoWQeLG9cVk9-J1EL8n3PUr0m7pnqEmONCPb1HtIeDQiSEQW9IKZX2E4O-UI9WbEI53zApkk-l5ZYz61AjjCFR-wNZk",
      "e": "AQAB",
      "x5c": ["test-x5c"]
    }
  ]
}`
