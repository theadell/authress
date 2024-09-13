package authress

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"
)

var RSAPrvKey *rsa.PrivateKey
var RSAPubKey *rsa.PublicKey

func TestMain(m *testing.M) {

	var err error
	RSAPrvKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(fmt.Sprintf("failed to generate RSA key pair: %v", err))
	}
	RSAPubKey = &RSAPrvKey.PublicKey
	exitCode := m.Run()

	os.Exit(exitCode)
}

func TestNewValidator(t *testing.T) {
	// Prepare keys and metadata for the tests
	keys := make(map[string]*rsa.PublicKey)
	keyID := "0"
	keys[keyID] = RSAPubKey

	validMetadata := &OAuth2ServerMetadata{
		Issuer:                "my-iss",
		IntrospectionEndpoint: "https://auth-server.com/introspect",
	}

	// Test cases
	tests := []struct {
		name        string
		options     []Option
		expectedErr bool
	}{
		{
			name: "valid with static metadata",
			options: []Option{
				WithMetadata(&OAuth2ServerMetadata{}),
				WithJWKS(newTestStore(RSAPubKey)),
			},
			expectedErr: false,
		},
		{
			name: "missing both discovery URL and metadata",
			options: []Option{
				WithMetadata(&OAuth2ServerMetadata{
					Issuer: "my-iss",
				}),
				WithAudienceValidation("aud"),
			},
			expectedErr: true,
		},
		{
			name: "valid with discovery URL",
			options: []Option{
				WithDiscovery("https://accounts.google.com/.well-known/openid-configuration"),
			},
			expectedErr: false,
		},
		{
			name: "introspection enabled but no endpoint",
			options: []Option{
				WithMetadata(&OAuth2ServerMetadata{
					Issuer: "my-iss",
				}),
				WithJWKS(newTestStore(RSAPubKey)),
				WithIntrospection("", ""),
			},
			expectedErr: true,
		},
		{
			name: "valid with custom HTTP client",
			options: []Option{
				WithMetadata(validMetadata),
				WithJWKS(newTestStore(RSAPubKey)),
				WithHTTPClient(&http.Client{}),
			},
			expectedErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			validator, err := New(tt.options...)

			if tt.expectedErr == false && err != nil {
				t.Fatalf("expected no error, but got: %v", err)
			}

			if tt.expectedErr == false && validator == nil {
				t.Fatalf("expected validator to be created, but got nil")
			}
		})
	}
}

func TestValidateToken(t *testing.T) {

	keys := make(map[string]*rsa.PublicKey)
	keyID := "0"
	keys[keyID] = RSAPubKey
	metaData := &OAuth2ServerMetadata{
		Issuer: "my-iss",
	}

	// Initialize the TokenValidator
	v, err := New(WithMetadata(metaData), WithJWKS(newTestStore(RSAPubKey)))
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	// Test cases
	tests := []struct {
		name        string
		tokenFunc   func() (string, error)
		expectedErr bool
	}{
		{
			name: "valid JWT",
			tokenFunc: func() (string, error) {
				claims := claimsMap{
					"exp":           time.Now().Add(time.Hour * 24).Unix(),
					"iat":           time.Now().Unix(),
					"iss":           "my-iss",
					"nonce":         "random-nonce",
					"acr":           "acr-value",
					"amr":           "amr-value",
					"azp":           "azp-value",
					"aud":           "audience",
					"custom-claim":  "custom-value",
					"another-claim": 12345,
				}
				return createSignedJWT(claims, RSAPrvKey, rs256, keyID)
			},
			expectedErr: false,
		},
		{
			name: "tampered JWT (audience mismatch)",
			tokenFunc: func() (string, error) {
				claims := claimsMap{
					"exp":           time.Now().Add(time.Hour * 24).Unix(),
					"iat":           time.Now().Unix(),
					"iss":           "my-iss",
					"nonce":         "random-nonce",
					"acr":           "acr-value",
					"amr":           "amr-value",
					"azp":           "azp-value",
					"aud":           "audience", // Will tamper this later
					"custom-claim":  "custom-value",
					"another-claim": 12345,
				}
				return createTamperedJWT(claims, RSAPrvKey, rs256, keyID, "aud", "new-aud")
			},
			expectedErr: true,
		},
		{
			name: "not a JWT",
			tokenFunc: func() (string, error) {
				// Return a non-JWT string
				return "not-a-jwt", nil
			},
			expectedErr: true,
		},
		{
			name: "expired JWT",
			tokenFunc: func() (string, error) {
				claims := claimsMap{
					"exp":           time.Now().Add(-time.Hour * 24).Unix(),
					"iat":           time.Now().Add(-time.Hour * 48).Unix(),
					"iss":           "my-iss",
					"nonce":         "random-nonce",
					"acr":           "acr-value",
					"amr":           "amr-value",
					"azp":           "azp-value",
					"aud":           "audience",
					"custom-claim":  "custom-value",
					"another-claim": 12345,
				}
				return createSignedJWT(claims, RSAPrvKey, rs256, keyID)
			},
			expectedErr: true,
		},
		{
			name: "invalid issuer",
			tokenFunc: func() (string, error) {
				claims := claimsMap{
					"exp":           time.Now().Add(time.Hour * 24).Unix(),
					"iat":           time.Now().Unix(),
					"iss":           "wrong-iss",
					"nonce":         "random-nonce",
					"acr":           "acr-value",
					"amr":           "amr-value",
					"azp":           "azp-value",
					"aud":           "audience",
					"custom-claim":  "custom-value",
					"another-claim": 12345,
				}
				return createSignedJWT(claims, RSAPrvKey, rs256, keyID)
			},
			expectedErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate the token
			token, err := tt.tokenFunc()
			if err != nil {
				t.Fatalf("failed to create token: %v", err)
			}

			// Validate the token
			_, err = v.ValidateJWT(token)

			// Check if the expected error matches the actual error
			if tt.expectedErr == false && err != nil {
				t.Fatalf("expected no error, but got: %v", err)
			}
		})
	}
}

func TestValidateTokenWithAudienceValidation(t *testing.T) {
	keys := make(map[string]*rsa.PublicKey)
	keyID := "0"
	keys[keyID] = RSAPubKey
	metaData := &OAuth2ServerMetadata{
		Issuer: "my-iss",
	}

	v, err := New(WithMetadata(metaData), WithJWKS(newTestStore(RSAPubKey)), WithAudienceValidation("my-app"))
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	validAudience := claimsMap{
		"exp": time.Now().Add(time.Hour * 24).Unix(),
		"iat": time.Now().Unix(),
		"iss": "my-iss",
		"aud": "my-app",
	}
	invalidAudience := claimsMap{
		"exp": time.Now().Add(time.Hour * 24).Unix(),
		"iat": time.Now().Unix(),
		"iss": "my-iss",
		"aud": "not-my-app",
	}

	tests := []struct {
		Name            string
		CreateTokenFunc func() (string, error)
		ExpectErr       bool
	}{
		{
			Name: "Valid Audience",
			CreateTokenFunc: func() (string, error) {
				return createSignedJWT(validAudience, RSAPrvKey, rs256, keyID)
			},
			ExpectErr: false,
		},
		{
			Name: "Invliad Audience",
			CreateTokenFunc: func() (string, error) {
				return createSignedJWT(invalidAudience, RSAPrvKey, rs256, keyID)
			},
			ExpectErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			token, err := tt.CreateTokenFunc()
			if err != nil {
				t.Fatalf("failed to create token: %v", err)
			}
			_, err = v.ValidateJWT(token)

			if tt.ExpectErr == false && err != nil {
				t.Fatalf("expected no error, but got: %v", err)
			}

		})
	}
}
