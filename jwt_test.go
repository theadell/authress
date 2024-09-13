package authress

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestValidateJWT(t *testing.T) {

	rsaPrivKey, rsaPubKey := generateRsaKeyPair(t, 2048)

	createJWT := func(issuer string, exp, nbf int64, aud []string) (*Token, string) {
		claims := claimsMap{
			"iss": issuer,
			"exp": exp,
			"nbf": nbf,
			"aud": aud,
		}
		tokenString, err := createSignedJWT(claims, rsaPrivKey, "RS256", "test-kid")
		if err != nil {
			t.Fatalf("failed to create signed JWT: %v", err)
		}

		token, err := parse([]byte(tokenString))
		if err != nil {
			t.Fatalf("failed to decode JWT: %v", err)
		}
		return token, tokenString
	}

	testCases := []struct {
		name           string
		issuer         string
		expectedIssuer string
		exp            int64
		nbf            int64
		validateAud    bool
		aud            []string
		expectedAud    []string
		expectErr      bool
		err            error
	}{
		{
			name:           "Valid Token",
			issuer:         "valid-issuer",
			expectedIssuer: "valid-issuer",
			exp:            time.Now().Add(1 * time.Hour).Unix(),
			nbf:            time.Now().Add(-1 * time.Hour).Unix(),
			validateAud:    true,
			aud:            []string{"expected-audience"},
			expectedAud:    []string{"expected-audience"},
			expectErr:      false,
		},
		{
			name:           "Expired Token",
			issuer:         "valid-issuer",
			expectedIssuer: "valid-issuer",
			exp:            time.Now().Add(-1 * time.Hour).Unix(),
			nbf:            time.Now().Add(-2 * time.Hour).Unix(),
			validateAud:    true,
			aud:            []string{"expected-audience"},
			expectedAud:    []string{"expected-audience"},
			expectErr:      true,
			err:            ErrTokenExpired,
		},
		{
			name:           "Token Not Valid Yet",
			issuer:         "valid-issuer",
			expectedIssuer: "valid-issuer",
			exp:            time.Now().Add(1 * time.Hour).Unix(),
			nbf:            time.Now().Add(1 * time.Hour).Unix(),
			validateAud:    true,
			aud:            []string{"expected-audience"},
			expectedAud:    []string{"expected-audience"},
			expectErr:      true,
			err:            ErrTokenNotYetValid,
		},
		{
			name:           "Invalid Issuer",
			issuer:         "invalid-issuer",
			expectedIssuer: "another-issuer",
			exp:            time.Now().Add(1 * time.Hour).Unix(),
			nbf:            time.Now().Add(-1 * time.Hour).Unix(),
			validateAud:    true,
			aud:            []string{"expected-audience"},
			expectedAud:    []string{"expected-audience"},
			expectErr:      true,
			err:            ErrInvalidIssuer,
		},
		{
			name:           "Invalid Audience",
			issuer:         "valid-issuer",
			expectedIssuer: "valid-issuer",
			exp:            time.Now().Add(1 * time.Hour).Unix(),
			nbf:            time.Now().Add(-1 * time.Hour).Unix(),
			validateAud:    true,
			aud:            []string{"wrong-audience"},
			expectedAud:    []string{"expected-audience"},
			expectErr:      true,
			err:            ErrInvalidAudience,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			token, _ := createJWT(tc.issuer, tc.exp, tc.nbf, tc.aud)

			_, err := validateJWT(token, rsaPubKey, tc.expectedIssuer, tc.validateAud, tc.expectedAud)

			if tc.expectErr {
				if err == nil {
					t.Errorf("expected an error but got none")
				} else if !errors.Is(err, tc.err) {
					t.Errorf("expected error message to contain %q, but got %q", tc.err.Error(), err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("did not expect an error but got: %v", err)
				}
			}

		})
	}
}

func TestParse(t *testing.T) {
	claims := claimsMap{
		"exp":           time.Now().Add(time.Hour * 24).Unix(),
		"iat":           time.Now().Unix(),
		"iss":           "issuer",
		"nonce":         "random-nonce",
		"acr":           "acr-value",
		"amr":           "amr-value",
		"azp":           "azp-value",
		"aud":           "audience",
		"custom-claim":  "custom-value",
		"another-claim": 12345,
	}

	privateKey, _ := generateRsaKeyPair(t, 2048)
	tokenString, err := createSignedJWT(claims, privateKey, "RS256", "id")
	if err != nil {
		t.Fatalf("failed to create signed JWT: %v", err)
	}

	token, err := parse([]byte(tokenString))
	if err != nil {
		t.Fatalf("failed to decode JWT: %v", err)
	}

	if token.header.Alg != "RS256" {
		t.Errorf("expected Alg to be RS256, got %s", token.header.Alg)
	}
	nonce := token.Claims.GetStringClaim("nonce")
	if token.Claims.Issuer != "issuer" || nonce != "random-nonce" {
		t.Errorf("decoded payload doesn't match the original values")
	}
	customClaim := token.Claims.GetStringClaim("custom-claim")
	if customClaim != "custom-value" {
		t.Errorf("expected custom-claim to be 'custom-value', got %v", customClaim)
	}

	anotherClaim := token.Claims.GetIntClaim("another-claim")
	if anotherClaim != 12345 {
		t.Errorf("expected another-claim to be 12345, got %v", anotherClaim)
	}
}

func TestParseClaims(t *testing.T) {
	/*
		{
		  "sub": "1234567890",
		  "name": "John Doe",
		  "email": "john.doe@example.com",
		  "email_verified": true,
		  "iat": 1609459200,
		  "exp": 1701880800,
		  "nbf": 1609459200,
		  "role": "admin",
		  "permissions": ["read", "write"],
		  "organization": {
		    "name": "Example Corp",
		    "department": {
		      "name": "Engineering",
		      "manager": {
		        "name": "Alice Smith",
		        "email": "alice.smith@example.com"
		      }
		    }
		  }
		}
	*/
	jwt := "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6IjIwNDM1NTNhNTY3N2M4NTEwMDA3YWYyNTRmYTNlYzc4In0." +
		"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZW1haWwiOiJqb2huLmRvZUBleGFtcGxlLmNvbSIsImVtYWls" +
		"X3ZlcmlmaWVkIjp0cnVlLCJpYXQiOjE2MDk0NTkyMDAsImV4cCI6MTcwMTg4MDgwMCwibmJmIjoxNjA5NDU5MjAwLCJyb2xlIjoi" +
		"YWRtaW4iLCJwZXJtaXNzaW9ucyI6WyJyZWFkIiwid3JpdGUiXSwib3JnYW5pemF0aW9uIjp7Im5hbWUiOiJFeGFtcGxlIENvcnAiL" +
		"CJkZXBhcnRtZW50Ijp7Im5hbWUiOiJFbmdpbmVlcmluZyIsIm1hbmFnZXIiOnsibmFtZSI6IkFsaWNlIFNtaXRoIiwiZW1haWwiOi" +
		"JhbGljZS5zbWl0aEBleGFtcGxlLmNvbSJ9fX19.aEYrqoezduJ4lutNThyufqXiR77FJKzHbJo25rkyM4QXOaR25EBQwsoJkA-Rri" +
		"AZRiYrcor-y6KLMXAxop83sQ"

	token, err := parse([]byte(jwt))
	if err != nil {
		t.Fatalf("expected valid JWT but got error: %v", err)
	}

	if token.Subject != "1234567890" {
		t.Errorf("expected subject 1234567890 but got %s", token.Subject)
	}
	if token.Name != "John Doe" {
		t.Errorf("expected name John Doe but got %s", token.Name)
	}
	if token.Email != "john.doe@example.com" {
		t.Errorf("expected email john.doe@example.com but got %s", token.Email)
	}
	if !token.EmailVerified {
		t.Errorf("expected email_verified to be true but got false")
	}

	expectedExpiry := time.Unix(1701880800, 0)
	if !token.ExpiresAtTime().Equal(expectedExpiry) {
		t.Errorf("expected expiration time %v but got %v", expectedExpiry, token.ExpiresAtTime())
	}

	if role, ok := token.GetClaim("role"); !ok || role != "admin" {
		t.Errorf("expected role admin but got %v", role)
	}

	if permissions, ok := token.GetClaim("permissions"); ok {
		if permList, ok := permissions.([]interface{}); ok {
			if len(permList) != 2 || permList[0] != "read" || permList[1] != "write" {
				t.Errorf("expected permissions [read, write] but got %v", permList)
			}
		} else {
			t.Errorf("permissions claim has wrong type")
		}
	} else {
		t.Errorf("expected permissions claim but not found")
	}

	type manager struct {
		Name  string `json:"name"`
		Email string `json:"email"`
	}

	type department struct {
		Name    string  `json:"name"`
		Manager manager `json:"manager"`
	}

	type organization struct {
		Name       string     `json:"name"`
		Department department `json:"department"`
	}

	var org *organization

	orgClaim, ok := token.GetClaim("organization")
	if !ok {
		t.Errorf("expected organization claim but not found")
	}

	orgBytes, err := json.Marshal(orgClaim)
	if err != nil {
		t.Fatalf("failed to marshal organization claim: %v", err)
	}

	err = json.Unmarshal(orgBytes, &org)
	if err != nil {
		t.Fatalf("failed to unmarshal organization claim: %v", err)
	}

	if org.Name != "Example Corp" {
		t.Errorf("expected organization name Example Corp but got %s", org.Name)
	}
	if org.Department.Name != "Engineering" {
		t.Errorf("expected department name Engineering but got %s", org.Department.Name)
	}
	if org.Department.Manager.Name != "Alice Smith" {
		t.Errorf("expected manager name Alice Smith but got %s", org.Department.Manager.Name)
	}
	if org.Department.Manager.Email != "alice.smith@example.com" {
		t.Errorf("expected manager email alice.smith@example.com but got %s", org.Department.Manager.Email)
	}

}

func TestParseErr(t *testing.T) {
	tests := []struct {
		name        string
		token       string
		expectedErr error
	}{
		{
			name:        "Invalid JWT (no periods)",
			token:       "invalidjwt",
			expectedErr: ErrInvalidJWT,
		},
		{
			name:        "Invalid JWT (only one period)",
			token:       "header.payload",
			expectedErr: ErrInvalidJWT,
		},
		{
			name:        "Invalid JWT (bad header base64)",
			token:       "invalidHeader.payload.signature",
			expectedErr: ErrInvalidJWT,
		},
		{
			name:        "Invalid JWT (bad payload base64)",
			token:       "eyJhbGciOiAiUlMyNTYifQ.invalidPayload.signature",
			expectedErr: ErrInvalidJWT,
		},
		{
			name:        "Invalid JWT (bad signature base64)",
			token:       "eyJhbGciOiAiUlMyNTYifQ.payload.invalidSignature",
			expectedErr: ErrInvalidJWT,
		},
		{
			name:        "Invalid JWT (invalid JSON header)",
			token:       "eyJhbGciOiAiUlMyNTYifQ==.eyJzdWIiOiIxMjM0NTY3ODkwIn0=.signature",
			expectedErr: ErrInvalidJWT,
		},
		{
			name:        "Invalid JWT (invalid JSON claims)",
			token:       "eyJhbGciOiAiUlMyNTYifQ.eyJzdWIiOiIxMjM0NTY3ODkwIn0=.signature",
			expectedErr: ErrInvalidJWT,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parse([]byte(tt.token))
			if !errors.Is(err, tt.expectedErr) {
				t.Errorf("expected error %v, got %v", tt.expectedErr, err)
			}
		})
	}
}

func TestTokenClaims(t *testing.T) {
	rsaPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA private key: %v", err)
	}

	iss, aud, kid := "my-iss", audience{"aud1", "aud2", "aud3"}, "key-id"
	tt, err := createSignedJWT(claimsMap{"iss": iss, "aud": aud}, rsaPrivKey, rs256, kid)

	token, err := parse([]byte(tt))
	if err != nil {
		t.Fatalf("failed to decode token: %v", err)

	}
	if got, want := token.Alg(), rs256; got != want {
		t.Errorf("Alg(); got %q; want %q", got, want)
	}
	if got, want := token.Kid(), kid; got != want {
		t.Errorf("Kid(); got %q; want %q", got, want)
	}
	if got := token.Claims.GetStringClaim("iss"); got != iss {
		t.Errorf("iss= %q; want %q", got, iss)
	}

	if got := token.Claims.Audience; !reflect.DeepEqual(got, aud) {
		t.Errorf("aud= %q; want %q", got, aud)
	}

}

func createSignedJWT(claims claimsMap, privateKey crypto.PrivateKey, alg, kid string) (string, error) {

	builder := newJWTBuilder(alg, privateKey, claims)
	builder.setHeader("kid", kid)

	tokenString, err := builder.signAndBuild()
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func createTamperedJWT(claims claimsMap, privateKey crypto.PrivateKey, alg, kid string, tamperedKey string, tamperedValue any) (string, error) {

	tokenString, err := createSignedJWT(claims, privateKey, alg, kid)
	if err != nil {
		return "", err
	}

	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid JWT format")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}

	var payloadMap map[string]interface{}
	err = json.Unmarshal(payloadBytes, &payloadMap)
	if err != nil {
		return "", err
	}

	payloadMap[tamperedKey] = tamperedValue

	newPayloadBytes, err := json.Marshal(payloadMap)
	if err != nil {
		return "", err
	}

	parts[1] = base64.RawURLEncoding.EncodeToString(newPayloadBytes)

	tamperedToken := strings.Join(parts, ".")

	return tamperedToken, nil
}
