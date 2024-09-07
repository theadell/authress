package internal

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
)

// verifyRSASignature verifies the RSA signature of the JWT.
func VerifyRSASignature(data, signature string, alg string, pubKey *rsa.PublicKey) error {
	// Base64 URL-decode the signature
	sigBytes, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return err
	}

	var hashed []byte
	var hashFunc crypto.Hash

	switch alg {
	case "RS256":
		sum := sha256.Sum256([]byte(data))
		hashed = sum[:]
		hashFunc = crypto.SHA256
	case "RS384":
		sum := sha512.Sum384([]byte(data))
		hashed = sum[:]
		hashFunc = crypto.SHA384
	case "RS512":
		sum := sha512.Sum512([]byte(data))
		hashed = sum[:]
		hashFunc = crypto.SHA512

	default:
		return fmt.Errorf("unsupported signing algorithm: %s", alg)
	}

	// Verify the signature using the RSA public key
	err = rsa.VerifyPKCS1v15(pubKey, hashFunc, hashed, sigBytes)
	if err != nil {
		return errors.New("invalid JWT signature")
	}

	return nil
}
