package internal

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
)

type JWKS struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	N   string `json:"n"` // RSA modulus
	E   string `json:"e"` // RSA exponent
	Alg string `json:"alg"`
	Use string `json:"use"`
}

func JWKToRSAPublicKey(jwk JWK) (*rsa.PublicKey, error) {
	if jwk.Kty != "RSA" {
		return nil, errors.New("unsupported key type")
	}

	// Decode the base64url-encoded modulus and exponent
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, err
	}

	// Convert exponent bytes to an integer
	eInt := big.NewInt(0)
	eInt.SetBytes(eBytes)
	e := int(eInt.Int64())

	// Construct the RSA public key
	rsaPubKey := &rsa.PublicKey{
		N: big.NewInt(0).SetBytes(nBytes),
		E: e,
	}

	return rsaPubKey, nil
}

func FetchJWKS(client *http.Client, jwksUri string) (*JWKS, error) {
	resp, err := client.Get(jwksUri)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKs with error %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch JWKs with status code %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var jwks JWKS
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, fmt.Errorf("failed to decode JWKs: %w", err)
	}

	segJWKs := make([]JWK, 0, len(jwks.Keys))
	for _, v := range jwks.Keys {
		if v.Use == "sig" && v.Kty == "RSA" {
			segJWKs = append(segJWKs, v)
		}
	}
	if len(segJWKs) == 0 {
		return nil, errors.New("no signature RSA keys found in JWKS")
	}
	jwks.Keys = segJWKs
	return &jwks, nil
}
