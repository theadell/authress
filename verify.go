package authress

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"math/big"
)

type signatureVerifier func(data, signature []byte, pubKey crypto.PublicKey) error

const (
	edDSA string = "EdDSA"

	rs256 string = "RS256"
	rs384 string = "RS384"
	rs512 string = "RS512"

	es256 string = "ES256"
	es384 string = "ES384"
	es512 string = "ES512"
)

var verifiers = map[string]signatureVerifier{
	rs256: rsaVerifier(crypto.SHA256),
	rs384: rsaVerifier(crypto.SHA384),
	rs512: rsaVerifier(crypto.SHA512),
	es256: ecdsaVerifier(crypto.SHA256),
	es384: ecdsaVerifier(crypto.SHA384),
	es512: ecdsaVerifier(crypto.SHA512),
	edDSA: ed25519Verifier,
}

func verifySignature(data, signature []byte, alg string, pubKey crypto.PublicKey) error {
	verifier, ok := verifiers[alg]
	if !ok {
		return ErrUnsupportedAlgorithm
	}
	return verifier(data, signature, pubKey)
}

func rsaVerifier(hashFunc crypto.Hash) signatureVerifier {
	return func(data, signature []byte, pubKey crypto.PublicKey) error {
		pub, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			return ErrInvalidPublicKey
		}
		hashed, err := hash(data, hashFunc)
		if err != nil {
			return err
		}
		if err := rsa.VerifyPKCS1v15(pub, hashFunc, hashed, signature); err != nil {
			return ErrInvalidSignature
		}
		return nil
	}
}

func ecdsaVerifier(hashFunc crypto.Hash) signatureVerifier {
	return func(data, signature []byte, pubKey crypto.PublicKey) error {
		pub, ok := pubKey.(*ecdsa.PublicKey)
		if !ok {
			return ErrInvalidPublicKey
		}
		hashDigest, err := hash(data, hashFunc)
		if err != nil {
			return err
		}
		r := new(big.Int).SetBytes(signature[:len(signature)/2])
		s := new(big.Int).SetBytes(signature[len(signature)/2:])
		if !ecdsa.Verify(pub, hashDigest, r, s) {
			return ErrInvalidSignature
		}
		return nil
	}
}

func ed25519Verifier(data, signature []byte, pubKey crypto.PublicKey) error {
	pub, ok := pubKey.(ed25519.PublicKey)
	if !ok {
		return ErrInvalidPublicKey
	}
	if !ed25519.Verify(pub, data, signature) {
		return ErrInvalidSignature
	}
	return nil
}

func hash(data []byte, hashFunc crypto.Hash) ([]byte, error) {
	hasher := hashFunc.New()
	_, err := hasher.Write(data)
	if err != nil {
		return nil, err
	}
	d := hasher.Sum(nil)
	return d, nil
}
