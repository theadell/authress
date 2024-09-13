package authress

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
)

func TestSignAndVerifyPositiveCases(t *testing.T) {

	data := []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit")

	rsaPrivateKey2048, rsaPublicKey2048 := generateRsaKeyPair(t, 2048)
	rsaPrivateKey3072, rsaPublicKey3072 := generateRsaKeyPair(t, 3072)
	rsaPrivateKey4096, rsaPublicKey4096 := generateRsaKeyPair(t, 4096)

	ecdsaPrivateKeyP256, ecdsaPublicKeyP256 := generateECDSAKeyPair(t, elliptic.P256())
	ecdsaPrivateKeyP384, ecdsaPublicKeyP384 := generateECDSAKeyPair(t, elliptic.P384())
	ecdsaPrivateKeyP521, ecdsaPublicKeyP521 := generateECDSAKeyPair(t, elliptic.P521())

	ed25519PrivateKey, ed25519PublicKey := generateEd25519KeyPair(t)

	hmacSecretKey256 := generateHMACSecret(t, 32) // HS256
	hmacSecretKey384 := generateHMACSecret(t, 48) // HS384
	hmacSecretKey512 := generateHMACSecret(t, 64) // HS512

	tests := []struct {
		name    string
		alg     string
		privKey crypto.PrivateKey
		pubKey  crypto.PublicKey
	}{
		{
			name:    "RS256",
			alg:     rs256,
			privKey: rsaPrivateKey2048,
			pubKey:  rsaPublicKey2048,
		},
		{
			name:    "RS384",
			alg:     rs384,
			privKey: rsaPrivateKey3072,
			pubKey:  rsaPublicKey3072,
		},
		{
			name:    "RS512",
			alg:     rs512,
			privKey: rsaPrivateKey4096,
			pubKey:  rsaPublicKey4096,
		},
		{
			name:    "ES256",
			alg:     es256,
			privKey: ecdsaPrivateKeyP256,
			pubKey:  ecdsaPublicKeyP256,
		},
		{
			name:    "ES384",
			alg:     es384,
			privKey: ecdsaPrivateKeyP384,
			pubKey:  ecdsaPublicKeyP384,
		},
		{
			name:    "ES512",
			alg:     es512,
			privKey: ecdsaPrivateKeyP521,
			pubKey:  ecdsaPublicKeyP521,
		},
		{
			name:    "EdDSA",
			alg:     edDSA,
			privKey: ed25519PrivateKey,
			pubKey:  ed25519PublicKey,
		},
		{
			name:    "HS256",
			alg:     hs256,
			privKey: hmacSecretKey256,
			pubKey:  hmacSecretKey256,
		},
		{
			name:    "HS384",
			alg:     hs384,
			privKey: hmacSecretKey384,
			pubKey:  hmacSecretKey384,
		},
		{
			name:    "HS512",
			alg:     hs512,
			privKey: hmacSecretKey512,
			pubKey:  hmacSecretKey512,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			signature, err := signData(data, tt.alg, tt.privKey)
			if err != nil {
				t.Fatalf("Failed to sign data: %v", err)
			}

			err = verifySignature(data, signature, tt.alg, tt.pubKey)
			if err != nil {
				t.Fatalf("Verification failed: %v", err)
			}
		})
	}
}

func TestSignWithInvalidPrivateKey(t *testing.T) {

	data := []byte("Sample data")

	rsaPrivateKey, _ := generateRsaKeyPair(t, 2048)
	ed25519PrivateKey, _ := generateEd25519KeyPair(t)
	hmacSecretKey := generateHMACSecret(t, 32)

	tests := []struct {
		name    string
		alg     string
		privKey crypto.PrivateKey
	}{
		{
			name:    "RS256 with invalid private key",
			alg:     rs256,
			privKey: ed25519PrivateKey,
		},
		{
			name:    "EdDSA with invalid private key",
			alg:     edDSA,
			privKey: rsaPrivateKey,
		},
		{
			name:    "HS256 with invalid private key",
			alg:     hs256,
			privKey: rsaPrivateKey,
		},
		{
			name:    "ES256 with invalid private key",
			alg:     es256,
			privKey: hmacSecretKey,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			_, err := signData(data, tt.alg, tt.privKey)
			if err == nil {
				t.Fatalf("Expected signing to fail but it succeeded")
			}
			if !errors.Is(err, errInvalidPrivateKey) {
				t.Fatalf("Expected signing to be %v; got: %v", errInvalidPrivateKey, err)
			}
		})
	}
}

func generateRsaKeyPair(t *testing.T, len int) (crypto.PrivateKey, crypto.PublicKey) {
	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, len)
	if err != nil {
		t.Fatalf("Failed to generate RSA private key: %v", err)
	}
	rsaPublicKey := &rsaPrivateKey.PublicKey
	return rsaPrivateKey, rsaPublicKey
}

func generateECDSAKeyPair(t *testing.T, curve elliptic.Curve) (crypto.PrivateKey, crypto.PublicKey) {
	ecdsaPrivateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA private key: %v", err)
	}
	return ecdsaPrivateKey, &ecdsaPrivateKey.PublicKey
}

func generateEd25519KeyPair(t *testing.T) (crypto.PrivateKey, crypto.PublicKey) {
	ed25519PublicKey, ed25519PrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
	}
	return ed25519PrivateKey, ed25519PublicKey
}

func generateHMACSecret(t *testing.T, len int) []byte {
	h := make([]byte, len)
	_, err := rand.Read(h)
	if err != nil {
		t.Fatalf("Failed to generate HMAC secret key: %v", err)
	}
	return h
}
