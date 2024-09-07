package internal

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

func GenerateRsaKeyPair() (*rsa.PrivateKey, *rsa.PublicKey) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(fmt.Sprintf("failed to generate RSA key pair: %v", err))
	}
	return privateKey, &privateKey.PublicKey
}
