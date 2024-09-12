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
