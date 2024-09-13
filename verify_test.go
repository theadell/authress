package authress

import (
	"crypto"
	"crypto/elliptic"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestVerifySignature(t *testing.T) {

	rsaPrivKey, rsaPubKey := generateRsaKeyPair(t, 2048)

	ecdsaPrivKey256, ecdsaPubKey256 := generateECDSAKeyPair(t, elliptic.P256())
	ecdsaPrivKey384, ecdsaPubKey384 := generateECDSAKeyPair(t, elliptic.P384())
	ecdsaPrivKey521, ecdsaPubKey521 := generateECDSAKeyPair(t, elliptic.P521())

	ed25519PrivKey, ed25519PubKey := generateEd25519KeyPair(t)

	hs256Key := generateHMACSecret(t, 32)
	hs384Key := generateHMACSecret(t, 48)
	hs512Key := generateHMACSecret(t, 64)

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
		{
			name:        "Valid EdDSA",
			alg:         "EdDSA",
			privateKey:  ed25519PrivKey,
			publicKey:   ed25519PubKey,
			expectedAlg: "EdDSA",
			valid:       true,
		},
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
			claims := claimsMap{
				"sub": "1234567890",
				"aud": "test-audience",
				"exp": time.Now().Add(1 * time.Hour).Unix(),
			}

			createToken := func(tc testCase, claims claimsMap) (string, error) {
				if tc.tamper {
					return createTamperedJWT(claims, tc.privateKey, tc.alg, "test-key-id", "aud", "fake-aud")
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

func TestDataTampering(t *testing.T) {

	data := []byte("data")

	rsaPrivateKey, rsaPublicKey := generateRsaKeyPair(t, 2048)

	signature, err := signData(data, rs256, rsaPrivateKey)
	if err != nil {
		t.Fatalf("Failed to sign data: %v", err)
	}

	tamperedData := append([]byte{}, data...)
	tamperedData[0] ^= 0xFF

	err = verifySignature(tamperedData, signature, rs256, rsaPublicKey)
	if err == nil {
		t.Fatalf("Verification should have failed for tampered data")
	}
}

func TestSignatureTampering(t *testing.T) {
	data := []byte("Sample data")

	rsaPrivateKey, rsaPublicKey := generateRsaKeyPair(t, 2048)

	signature, err := signData(data, rs256, rsaPrivateKey)
	if err != nil {
		t.Fatalf("Failed to sign data: %v", err)
	}

	tamperedSignature := append([]byte{}, signature...)
	tamperedSignature[0] ^= 0xFF

	err = verifySignature(data, tamperedSignature, rs256, rsaPublicKey)
	if err == nil {
		t.Fatalf("Verification should have failed for tampered signature")
	}
}
