package internal

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestValidateJWT(t *testing.T) {

	rsaPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA private key: %v", err)
	}
	rsaPubKey := &rsaPrivKey.PublicKey

	createJWT := func(issuer string, exp, nbf int64, aud []string) (*Token, string) {
		claims := jwt.MapClaims{
			"iss": issuer,
			"exp": exp,
			"nbf": nbf,
			"aud": aud,
		}
		tokenString, err := CreateSignedJWT(claims, rsaPrivKey, "RS256", "test-kid")
		if err != nil {
			t.Fatalf("failed to create signed JWT: %v", err)
		}

		token, err := DecodeJWT(tokenString)
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
		errMessage     string
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
			errMessage:     "[claims]",
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
			errMessage:     "[claims]",
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
			errMessage:     "[claims]",
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
			errMessage:     "[claims]",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			token, _ := createJWT(tc.issuer, tc.exp, tc.nbf, tc.aud)

			_, err := ValidateJWT(token, rsaPubKey, tc.expectedIssuer, tc.validateAud, tc.expectedAud)

			if tc.expectErr {
				if err == nil {
					t.Errorf("expected an error but got none")
				} else if tc.errMessage != "" && !strings.Contains(err.Error(), tc.errMessage) {
					t.Errorf("expected error message to contain %q, but got %q", tc.errMessage, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("did not expect an error but got: %v", err)
				}
			}

		})
	}
}

func TestDecodeJWT(t *testing.T) {
	claims := jwt.MapClaims{
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

	privateKey, _ := GenerateRsaKeyPair()
	tokenString, err := CreateSignedJWT(claims, privateKey, "RS256", "id")
	if err != nil {
		t.Fatalf("failed to create signed JWT: %v", err)
	}

	token, err := DecodeJWT(tokenString)
	if err != nil {
		t.Fatalf("failed to decode JWT: %v", err)
	}

	if token.Header.Alg != "RS256" {
		t.Errorf("expected Alg to be RS256, got %s", token.Header.Alg)
	}
	nonce, _ := token.GetStringClaim("nonce")
	if token.Iss != "issuer" || nonce != "random-nonce" {
		t.Errorf("decoded payload doesn't match the original values")
	}
	customClaim, ok := token.GetStringClaim("custom-claim")
	if !ok || customClaim != "custom-value" {
		t.Errorf("expected custom-claim to be 'custom-value', got %v", customClaim)
	}

	anotherClaim, _ := token.GetInt64Claim("another-claim")
	if anotherClaim != 12345 {
		t.Errorf("expected another-claim to be 12345, got %v", anotherClaim)
	}
}

func TestVerifySignature(t *testing.T) {

	// RSA key pair
	rsaPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA private key: %v", err)
	}
	rsaPubKey := &rsaPrivKey.PublicKey

	// ECDSA key pair (P-256)
	ecdsaPrivKey256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA P-256 private key: %v", err)
	}
	ecdsaPubKey256 := &ecdsaPrivKey256.PublicKey

	// ECDSA key pair (P-384)
	ecdsaPrivKey384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA P-384 private key: %v", err)
	}
	ecdsaPubKey384 := &ecdsaPrivKey384.PublicKey

	// ECDSA key pair (P-521)
	ecdsaPrivKey521, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA P-521 private key: %v", err)
	}
	ecdsaPubKey521 := &ecdsaPrivKey521.PublicKey

	// EdDSA (Ed25519) key pair
	ed25519PubKey, ed25519PrivKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 key: %v", err)
	}

	// HS256 (HMAC with SHA-256) secret key
	hs256 := make([]byte, 32)
	rand.Read(hs256)

	type testCase struct {
		name        string
		alg         string
		privateKey  crypto.PrivateKey
		publicKey   crypto.PublicKey
		expectedAlg string
		valid       bool
		modifySig   bool
		modifyData  bool
		tamper      bool
	}

	testCases := []testCase{
		// RSA algorithm
		{
			name:        "Valid RS256",
			alg:         "RS256",
			privateKey:  rsaPrivKey,
			publicKey:   rsaPubKey,
			expectedAlg: "RS256",
			valid:       true,
		},
		{
			name:        "Valid RS384",
			alg:         "RS384",
			privateKey:  rsaPrivKey,
			publicKey:   rsaPubKey,
			expectedAlg: "RS384",
			valid:       true,
		},
		{
			name:        "Valid RS512",
			alg:         "RS512",
			privateKey:  rsaPrivKey,
			publicKey:   rsaPubKey,
			expectedAlg: "RS512",
			valid:       true,
		},
		// ECDSA algorithm
		{
			name:        "Valid ES256",
			alg:         "ES256",
			privateKey:  ecdsaPrivKey256,
			publicKey:   ecdsaPubKey256,
			expectedAlg: "ES256",
			valid:       true,
		},
		{
			name:        "Valid ES384",
			alg:         "ES384",
			privateKey:  ecdsaPrivKey384,
			publicKey:   ecdsaPubKey384,
			expectedAlg: "ES384",
			valid:       true,
		},
		{
			name:        "Valid ES512",
			alg:         "ES512",
			privateKey:  ecdsaPrivKey521,
			publicKey:   ecdsaPubKey521,
			expectedAlg: "ES512",
			valid:       true,
		},
		// EdDSA algorithm
		{
			name:        "Valid EdDSA",
			alg:         "EdDSA",
			privateKey:  ed25519PrivKey,
			publicKey:   ed25519PubKey,
			expectedAlg: "EdDSA",
			valid:       true,
		},
		// Invalid/Tampered cases
		{
			name:        "Invalid Signature (Modified Signature) RS256",
			alg:         "RS256",
			privateKey:  rsaPrivKey,
			publicKey:   rsaPubKey,
			expectedAlg: "RS256",
			valid:       false,
			modifySig:   true,
		},
		{
			name:        "Invalid Signature (Modified Data) RS256",
			alg:         "RS256",
			privateKey:  rsaPrivKey,
			publicKey:   rsaPubKey,
			expectedAlg: "RS256",
			valid:       false,
			modifyData:  true,
		},
		{
			name:        "Tampered RSA256",
			alg:         "RS256",
			privateKey:  rsaPrivKey,
			publicKey:   rsaPubKey,
			expectedAlg: "RS256",
			valid:       false,
			tamper:      true,
		},
		{
			name:        "Tampered EdDSA",
			alg:         "EdDSA",
			privateKey:  ed25519PrivKey,
			publicKey:   ed25519PubKey,
			expectedAlg: "EdDSA",
			valid:       false,
			tamper:      true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			claims := jwt.MapClaims{
				"sub": "1234567890",
				"aud": "test-audience",
				"exp": time.Now().Add(1 * time.Hour).Unix(),
			}

			createToken := func(tc testCase, claims jwt.MapClaims) (string, error) {
				if tc.tamper {
					return CreateTamperedJWT(claims, tc.privateKey, tc.alg, "test-key-id", "aud", "fake-aud")
				}
				return CreateSignedJWT(claims, tc.privateKey, tc.alg, "test-key-id")
			}

			tokenString, err := createToken(tc, claims)
			if err != nil {
				t.Fatalf("failed to create JWT: %v", err)
			}

			header, payload, signature, err := Split(tokenString)
			if err != nil {
				t.Fatalf("failed to split token: %v", err)
			}

			data := header + "." + payload

			if tc.modifySig {
				signature = "invalidsignature"
			}

			if tc.modifyData {
				data = "tampered.header.payload"
			}

			err = VerifySignature(data, signature, tc.expectedAlg, tc.publicKey)

			if tc.valid && err != nil {
				t.Errorf("expected valid signature but got error: %v", err)
			} else if !tc.valid && err == nil {
				t.Errorf("expected invalid signature but verification succeeded")
			}
		})
	}
}

func TestTokenClaims(t *testing.T) {
	rsaPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA private key: %v", err)
	}

	iss, aud := "my-iss", []string{"aud1", "aud2", "aud3"}
	tt, err := CreateSignedJWT(jwt.MapClaims{"iss": iss, "aud": aud}, rsaPrivKey, "RS256", "key")

	token, err := DecodeJWT(tt)
	if err != nil {
		t.Fatalf("failed to decode token: %v", err)

	}
	if got, _ := token.GetStringClaim("iss"); got != iss {
		t.Errorf("iss= %q; want %q", got, iss)
	}

	if got, _ := token.GetAudience(); !reflect.DeepEqual(got, aud) {
		t.Errorf("iss= %q; want %q", got, aud)
	}

}

func CreateSignedJWT(claims jwt.MapClaims, privateKey crypto.PrivateKey, alg, kid string) (string, error) {
	var signingMethod jwt.SigningMethod

	switch alg {
	case "RS256":
		signingMethod = jwt.SigningMethodRS256
	case "RS384":
		signingMethod = jwt.SigningMethodRS384
	case "RS512":
		signingMethod = jwt.SigningMethodRS512
	case "ES256":
		signingMethod = jwt.SigningMethodES256
	case "ES384":
		signingMethod = jwt.SigningMethodES384
	case "ES512":
		signingMethod = jwt.SigningMethodES512
	case "EdDSA":
		signingMethod = jwt.SigningMethodEdDSA
	case "HS256":
		signingMethod = jwt.SigningMethodHS256
	default:
		return "", fmt.Errorf("unsupported signing algorithm: %s", alg)
	}

	token := jwt.NewWithClaims(signingMethod, claims)

	token.Header["kid"] = kid

	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func CreateTamperedJWT(claims jwt.MapClaims, privateKey crypto.PrivateKey, alg, kid string, tamperedKey string, tamperedValue any) (string, error) {

	tokenString, err := CreateSignedJWT(claims, privateKey, alg, kid)
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
