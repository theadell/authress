package authress

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
)

type signatureSigner func(data []byte, privKey crypto.PrivateKey) ([]byte, error)

var signers = map[string]signatureSigner{
	rs256: rsaSigner(crypto.SHA256),
	rs384: rsaSigner(crypto.SHA384),
	rs512: rsaSigner(crypto.SHA512),
	es256: ecdsaSigner(crypto.SHA256),
	es384: ecdsaSigner(crypto.SHA384),
	es512: ecdsaSigner(crypto.SHA512),
	edDSA: ed25519Signer,
	hs256: hmacSigner(crypto.SHA256),
	hs384: hmacSigner(crypto.SHA384),
	hs512: hmacSigner(crypto.SHA512),
}

func signData(data []byte, alg string, privKey crypto.PrivateKey) ([]byte, error) {
	signer, ok := signers[alg]
	if !ok {
		return nil, errInvalidPrivateKey
	}
	return signer(data, privKey)
}

func rsaSigner(hashFunc crypto.Hash) signatureSigner {
	return func(data []byte, privKey crypto.PrivateKey) ([]byte, error) {
		priv, ok := privKey.(*rsa.PrivateKey)
		if !ok {
			return nil, errInvalidPrivateKey
		}
		hashed, err := hash(data, hashFunc)
		if err != nil {
			return nil, err
		}
		signature, err := rsa.SignPKCS1v15(rand.Reader, priv, hashFunc, hashed)
		if err != nil {
			return nil, err
		}
		return signature, nil
	}
}

func ecdsaSigner(hashFunc crypto.Hash) signatureSigner {
	return func(data []byte, privKey crypto.PrivateKey) ([]byte, error) {
		priv, ok := privKey.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errInvalidPrivateKey
		}
		hashDigest, err := hash(data, hashFunc)
		if err != nil {
			return nil, err
		}
		r, s, err := ecdsa.Sign(rand.Reader, priv, hashDigest)
		if err != nil {
			return nil, err
		}

		curveBits := priv.Curve.Params().BitSize
		keyBytes := (curveBits + 7) / 8

		rBytes := r.Bytes()
		sBytes := s.Bytes()

		// Pad r and s to the key size
		rPadded := make([]byte, keyBytes)
		sPadded := make([]byte, keyBytes)
		copy(rPadded[keyBytes-len(rBytes):], rBytes)
		copy(sPadded[keyBytes-len(sBytes):], sBytes)

		signature := append(rPadded, sPadded...)
		return signature, nil
	}
}

func ed25519Signer(data []byte, privKey crypto.PrivateKey) ([]byte, error) {
	priv, ok := privKey.(ed25519.PrivateKey)
	if !ok {
		return nil, errInvalidPrivateKey
	}
	signature := ed25519.Sign(priv, data)
	return signature, nil
}

func hmacSigner(hashFunc crypto.Hash) signatureSigner {
	return func(data []byte, privKey crypto.PrivateKey) ([]byte, error) {
		secretKey, ok := privKey.([]byte)
		if !ok {
			return nil, errInvalidPrivateKey
		}
		mac := hmac.New(hashFunc.New, secretKey)
		_, err := mac.Write(data)
		if err != nil {
			return nil, err
		}
		signature := mac.Sum(nil)
		return signature, nil
	}
}
