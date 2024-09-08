package internal

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestRealJWTDecoding(t *testing.T) {
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
	tokenString, err := CreateSignedJWT(claims, privateKey, "id")
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

func TestVerifyRSASignature(t *testing.T) {

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}
	pubKey := &privKey.PublicKey

	type testCase struct {
		name       string
		alg        string
		data       string
		hashFunc   crypto.Hash
		hashFuncFn func(data string) []byte
		valid      bool
	}

	testCases := []testCase{
		{
			name:     "Valid RS256",
			alg:      "RS256",
			data:     "header.payload",
			hashFunc: crypto.SHA256,
			hashFuncFn: func(data string) []byte {
				sum := sha256.Sum256([]byte(data))
				return sum[:]
			},
			valid: true,
		},
		{
			name:     "Valid RS384",
			alg:      "RS384",
			data:     "header.payload",
			hashFunc: crypto.SHA384,
			hashFuncFn: func(data string) []byte {
				sum := sha512.Sum384([]byte(data))
				return sum[:]
			},
			valid: true,
		},
		{
			name:     "Valid RS512",
			alg:      "RS512",
			data:     "header.payload",
			hashFunc: crypto.SHA512,
			hashFuncFn: func(data string) []byte {
				sum := sha512.Sum512([]byte(data))
				return sum[:]
			},
			valid: true,
		},
		{
			name:     "Invalid Signature",
			alg:      "RS256",
			data:     "header.payload",
			hashFunc: crypto.SHA256,
			hashFuncFn: func(data string) []byte {
				return []byte("invalidhash")
			},
			valid: false,
		},
		{
			name:     "Unspported Algorithm",
			alg:      "HS512",
			data:     "header.payload",
			hashFunc: crypto.SHA256,
			hashFuncFn: func(data string) []byte {
				sum := sha256.Sum256([]byte(data))
				return sum[:]
			},
			valid: false,
		},
	}

	// Step 3: Run through the test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Step 4: Hash the data
			hashed := tc.hashFuncFn(tc.data)

			// Step 5: Sign the data with the private key (if valid)
			var signature []byte
			if tc.valid {
				signature, err = rsa.SignPKCS1v15(rand.Reader, privKey, tc.hashFunc, hashed)
				if err != nil {
					t.Fatalf("failed to sign data: %v", err)
				}
			} else {
				signature = []byte("invalidsignature")
			}

			// Step 6: Base64 URL-encode the signature for the JWT-like structure
			sigEncoded := base64.RawURLEncoding.EncodeToString(signature)

			// Step 7: Call the function to verify the signature
			err = VerifyRSASignature(tc.data, sigEncoded, tc.alg, pubKey)

			// Step 8: Check the result
			if tc.valid && err != nil {
				t.Errorf("expected valid signature but got error: %v", err)
			} else if !tc.valid && err == nil {
				t.Errorf("expected invalid signature but verification succeeded")
			}
		})
	}
}

func CreateSignedJWT(claims jwt.MapClaims, privateKey *rsa.PrivateKey, kid string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func CreateTamperedJWT(claims jwt.MapClaims, privateKey *rsa.PrivateKey, kid string, tamperedKey string, tamperedValue any) (string, error) {
	// Step 1: Create a valid signed JWT
	tokenString, err := CreateSignedJWT(claims, privateKey, kid)
	if err != nil {
		return "", err
	}

	// Step 2: Split the token into its components (header, payload, signature)
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid JWT format")
	}

	// Step 3: Base64-decode the payload (the second part)
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}

	// Step 4: Unmarshal the payload into a map
	var payloadMap map[string]interface{}
	err = json.Unmarshal(payloadBytes, &payloadMap)
	if err != nil {
		return "", err
	}

	// Step 5: Tamper with the payload (modify or add a claim)
	payloadMap[tamperedKey] = tamperedValue

	// Step 6: Marshal the tampered payload back to JSON
	newPayloadBytes, err := json.Marshal(payloadMap)
	if err != nil {
		return "", err
	}

	// Step 7: Base64 URL-encode the tampered payload
	parts[1] = base64.RawURLEncoding.EncodeToString(newPayloadBytes)

	// Step 8: Reassemble the JWT with the original header and signature, but tampered payload
	tamperedToken := strings.Join(parts, ".")

	// Return the tampered JWT
	return tamperedToken, nil
}
