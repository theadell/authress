package internal

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
)

// verifyRSASignature verifies the RSA signature of the JWT.
func VerifySignature(data, signature string, alg string, pubKey crypto.PublicKey) error {
	// Base64 URL-decode the signature
	sigBytes, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return err
	}

	var hashed []byte
	var hashFunc crypto.Hash

	switch alg {
	case "RS256", "ES256":
		sum := sha256.Sum256([]byte(data))
		hashed = sum[:]
		hashFunc = crypto.SHA256
	case "RS384", "ES384":
		sum := sha512.Sum384([]byte(data))
		hashed = sum[:]
		hashFunc = crypto.SHA384
	case "RS512", "ES512":
		sum := sha512.Sum512([]byte(data))
		hashed = sum[:]
		hashFunc = crypto.SHA512
	case "EdDSA":
		hashed = []byte(data)
	default:
		return fmt.Errorf("unsupported signing algorithm: %s", alg)
	}

	switch pub := pubKey.(type) {
	case *rsa.PublicKey:
		err = rsa.VerifyPKCS1v15(pub, hashFunc, hashed, sigBytes)
		if err != nil {
			return errors.New("invalid RSA signature")
		}
	case *ecdsa.PublicKey:
		r := new(big.Int)
		s := new(big.Int)
		sigLen := len(sigBytes) / 2
		r.SetBytes(sigBytes[:sigLen])
		s.SetBytes(sigBytes[sigLen:])
		if !ecdsa.Verify(pub, hashed, r, s) {
			return errors.New("invalid ECDSA signature")
		}
	case ed25519.PublicKey:
		if !ed25519.Verify(pub, hashed, sigBytes) {
			return errors.New("invalid Ed25519 signature")
		}
	default:
		return fmt.Errorf("unsupported key type: %T", pubKey)
	}

	return nil
}
