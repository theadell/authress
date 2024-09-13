package authress

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

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

	hs256Key := make([]byte, 32)
	if _, err := rand.Read(hs256Key); err != nil {
		t.Fatalf("failed to generate HS256 secret key: %v", err)
	}

	hs384Key := make([]byte, 48)
	if _, err := rand.Read(hs384Key); err != nil {
		t.Fatalf("failed to generate HS384 secret key: %v", err)
	}

	hs512Key := make([]byte, 64)
	if _, err := rand.Read(hs512Key); err != nil {
		t.Fatalf("failed to generate HS512 secret key: %v", err)
	}

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
		{
			name:        "Invalid PublicKey Type for RS256",
			alg:         "RS256",
			privateKey:  rsaPrivKey,
			publicKey:   ecdsaPubKey256,
			expectedAlg: "RS256",
			valid:       false,
		},
		{
			name:        "Invalid PublicKey Type for ES512",
			alg:         "ES512",
			privateKey:  ecdsaPrivKey521,
			publicKey:   nil,
			expectedAlg: "ES512",
			valid:       false,
		},
		{
			name:        "Invalid Hash Function",
			alg:         "RS256",
			privateKey:  rsaPrivKey,
			publicKey:   rsaPubKey,
			expectedAlg: "InvalidAlg",
			valid:       false,
		},
		// HMAC
		{
			name:        "Valid HS256",
			alg:         "HS256",
			privateKey:  hs256Key,
			publicKey:   hs256Key,
			expectedAlg: "HS256",
			valid:       true,
		},
		{
			name:        "Valid HS384",
			alg:         "HS384",
			privateKey:  hs384Key,
			publicKey:   hs384Key,
			expectedAlg: "HS384",
			valid:       true,
		},
		{
			name:        "Valid HS512",
			alg:         "HS512",
			privateKey:  hs512Key,
			publicKey:   hs512Key,
			expectedAlg: "HS512",
			valid:       true,
		},
		// Invalid HMAC cases
		{
			name:        "Invalid Signature (Modified Signature) HS256",
			alg:         "HS256",
			privateKey:  hs256Key,
			publicKey:   hs256Key,
			expectedAlg: "HS256",
			valid:       false,
			modifySig:   true,
		},
		{
			name:        "Invalid Signature (Modified Data) HS256",
			alg:         "HS256",
			privateKey:  hs256Key,
			publicKey:   hs256Key,
			expectedAlg: "HS256",
			valid:       false,
			modifyData:  true,
		},
		{
			name:        "Invalid Secret Key HS256",
			alg:         "HS256",
			privateKey:  hs256Key,
			publicKey:   make([]byte, 32),
			expectedAlg: "HS256",
			valid:       false,
		},
		{
			name:        "Invalid Signature (Modified Signature) HS384",
			alg:         "HS384",
			privateKey:  hs384Key,
			publicKey:   hs384Key,
			expectedAlg: "HS384",
			valid:       false,
			modifySig:   true,
		},
		{
			name:        "Invalid Signature (Modified Data) HS384",
			alg:         "HS384",
			privateKey:  hs384Key,
			publicKey:   hs384Key,
			expectedAlg: "HS384",
			valid:       false,
			modifyData:  true,
		},
		{
			name:        "Invalid Secret Key HS384",
			alg:         "HS384",
			privateKey:  hs384Key,
			publicKey:   make([]byte, 48),
			expectedAlg: "HS384",
			valid:       false,
		},
		{
			name:        "Invalid Signature (Modified Signature) HS512",
			alg:         "HS512",
			privateKey:  hs512Key,
			publicKey:   hs512Key,
			expectedAlg: "HS512",
			valid:       false,
			modifySig:   true,
		},
		{
			name:        "Invalid Signature (Modified Data) HS512",
			alg:         "HS512",
			privateKey:  hs512Key,
			publicKey:   hs512Key,
			expectedAlg: "HS512",
			valid:       false,
			modifyData:  true,
		},
		{
			name:        "Invalid Secret Key HS512",
			alg:         "HS512",
			privateKey:  hs512Key,
			publicKey:   make([]byte, 64),
			expectedAlg: "HS512",
			valid:       false,
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
				return createSignedJWT(claims, tc.privateKey, tc.alg, "test-key-id")
			}

			tokenString, err := createToken(tc, claims)
			if err != nil {
				t.Fatalf("failed to create JWT: %v", err)
			}

			parts := strings.Split(tokenString, ".")
			if len(parts) != 3 {
				t.Fatal("failed to split token")
			}
			header := parts[0]
			payload := parts[1]
			signature := parts[2]
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

			sigBytes, err := base64.RawURLEncoding.DecodeString(signature)
			if err != nil {
				t.Fatal("failed to decode sig")
			}

			err = verifySignature([]byte(data), sigBytes, tc.expectedAlg, tc.publicKey)

			if tc.valid && err != nil {
				t.Errorf("expected valid signature but got error: %v", err)
			} else if !tc.valid && err == nil {
				t.Errorf("expected invalid signature but verification succeeded")
			}
		})
	}
}
