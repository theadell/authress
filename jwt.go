package authress

import (
	"bytes"
	"crypto"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

type jwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

type Token struct {
	raw    []byte
	header jwtHeader
	Claims
	sig  []byte
	sep1 int
	sep2 int
}

func (t *Token) Alg() string {
	return t.header.Alg
}

func (t *Token) Kid() string {
	return t.header.Kid
}

func parse(token []byte) (*Token, error) {

	var sep1, sep2 int
	if sep1, sep2 = bytes.IndexByte(token, '.'), bytes.LastIndexByte(token, '.'); sep2 <= sep1 {
		return nil, ErrInvalidJWT
	}

	buf := make([]byte, len(token))

	headerByteN, err := base64.RawURLEncoding.Decode(buf, token[:sep1])
	if err != nil {
		return nil, ErrInvalidJWT
	}
	var header jwtHeader
	if err := json.Unmarshal(buf[:headerByteN], &header); err != nil {
		return nil, ErrInvalidJWT
	}

	claimsBytesN, err := base64.RawURLEncoding.Decode(buf[headerByteN:], token[sep1+1:sep2])
	if err != nil {
		return nil, ErrInvalidJWT
	}

	var claims Claims
	if err := json.Unmarshal(buf[headerByteN:headerByteN+claimsBytesN], &claims); err != nil {
		return nil, ErrInvalidJWT
	}

	signN, err := base64.RawURLEncoding.Decode(buf[headerByteN+claimsBytesN:], token[sep2+1:])
	if err != nil {
		return nil, ErrInvalidJWT
	}

	signature := buf[headerByteN+claimsBytesN : headerByteN+claimsBytesN+signN]
	claims.rawPayload = buf[headerByteN : headerByteN+claimsBytesN]
	return &Token{
		raw:    token,
		header: header,
		Claims: claims,
		sig:    signature,
		sep1:   sep1,
		sep2:   sep2,
	}, nil
}

func validateJWT(t *Token, key crypto.PublicKey, issuer string, validateAud bool, aud []string) (*Token, error) {

	if err := verifySignature(t.raw[:t.sep2], t.sig, t.header.Alg, key); err != nil {
		return nil, ErrInvalidSignature
	}

	if !equal(t.Claims.Issuer, issuer) {
		return nil, fmt.Errorf("%w: got %s; want %s", ErrInvalidIssuer, t.Claims.Issuer, issuer)
	}

	now := time.Now().Unix()
	if now > t.Claims.ExpiresAt {
		return nil, ErrTokenExpired
	}

	if t.Claims.NotBefore > 0 && now < t.Claims.NotBefore {
		return nil, ErrTokenNotYetValid
	}

	if validateAud {
		if !t.Claims.hasAudience(aud...) {
			return nil, fmt.Errorf("%w: audience does not match: %v", ErrInvalidAudience, aud)
		}
	}

	return t, nil
}

func equal(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

/*
Should we introduce (export) JWT creation and signing into the package?
This will make it an end to end solution. but will introduce some complexity
TODO: What will the API look like
TODO: rewrite of the Token type?
*/
type claimsMap map[string]any
type jwtBuilder struct {
	alg    string
	key    crypto.PrivateKey
	header claimsMap
	claims claimsMap
}

func newJWTBuilder(alg string, key crypto.PrivateKey, claims claimsMap) *jwtBuilder {
	return &jwtBuilder{
		alg:    alg,
		key:    key,
		header: map[string]any{"alg": alg, "typ": "JWT"},
		claims: claims,
	}
}
func (b *jwtBuilder) setClaim(key string, value interface{}) *jwtBuilder {
	b.claims[key] = value
	return b
}

func (b *jwtBuilder) setHeader(key string, value interface{}) *jwtBuilder {
	b.header[key] = value
	return b
}

func (b *jwtBuilder) signAndBuild() (string, error) {

	headerJSON, err := json.Marshal(b.header)
	if err != nil {
		return "", err
	}
	headerEncoded := base64.RawURLEncoding.EncodeToString(headerJSON)

	claimsJSON, err := json.Marshal(b.claims)
	if err != nil {
		return "", err
	}
	claimsEncoded := base64.RawURLEncoding.EncodeToString(claimsJSON)

	signingInput := fmt.Sprintf("%s.%s", headerEncoded, claimsEncoded)

	var signature []byte
	signature, err = signData([]byte(signingInput), b.alg, b.key)
	if err != nil {
		return "", err
	}
	signatureEncoded := base64.RawURLEncoding.EncodeToString(signature)

	return fmt.Sprintf("%s.%s", signingInput, signatureEncoded), nil
}
