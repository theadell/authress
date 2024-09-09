package internal

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

type JWTHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

type Token struct {
	raw    string
	Header JWTHeader
	Claims map[string]any
	Sig    string
	Iss    string
	Exp    int64
	Nbf    int64
	Aud    []string
}

func (t *Token) GetClaim(key string) (any, bool) {
	value, ok := t.Claims[key]
	return value, ok
}

func (t *Token) GetInt64Claim(key string) (int64, bool) {
	if val, ok := t.Claims[key].(float64); ok {
		return int64(val), true
	}
	return 0, false
}

func (t *Token) GetStringClaim(key string) (string, bool) {
	if val, ok := t.Claims[key].(string); ok {
		return val, true
	}
	return "", false
}

func (t *Token) GetAudience() ([]string, bool) {
	audClaim, ok := t.Claims["aud"]
	if !ok {
		return nil, false
	}

	// Handle the "aud" claim, which can be a string or a slice of strings
	switch v := audClaim.(type) {
	case string:
		return []string{v}, true
	case []any: // In case it's a slice of strings
		audList := make([]string, len(v))
		for i, audVal := range v {
			if audStr, ok := audVal.(string); ok {
				audList[i] = audStr
			}
		}
		return audList, true
	default:
		return nil, false
	}
}

func Split(token string) (string, string, string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", "", "", errors.New("invalid JWT structure")
	}
	return parts[0], parts[1], parts[2], nil
}

func decodeJWTPart(encodedPart string, out any) error {
	// Base64 URL-decode the part
	partBytes, err := base64.RawURLEncoding.DecodeString(encodedPart)
	if err != nil {
		return fmt.Errorf("failed to decode part: %w", err) // Wrapping the error for context without string concatenation
	}

	// Unmarshal the decoded bytes into the provided type (out)
	if err := json.Unmarshal(partBytes, &out); err != nil {
		return fmt.Errorf("failed to unmarshal part: %w", err)
	}

	return nil
}

func DecodeJWT(token string) (*Token, error) {
	encodedHeader, encodedPayload, sig, err := Split(token)
	if err != nil {
		return nil, err
	}

	var header JWTHeader
	if err := decodeJWTPart(encodedHeader, &header); err != nil {
		return nil, fmt.Errorf("failed to decode JWT header: %w", err)
	}

	// Decode the claims
	var claims map[string]any
	if err := decodeJWTPart(encodedPayload, &claims); err != nil {
		return nil, fmt.Errorf("failed to decode JWT claims: %w", err)
	}

	var issuer string
	if iss, ok := claims["iss"].(string); ok {
		issuer = iss
	}

	var expiration int64
	if exp, ok := claims["exp"].(float64); ok {
		expiration = int64(exp)
	}

	var notBefore int64
	if nbf, ok := claims["nbf"].(float64); ok {
		notBefore = int64(nbf)
	}

	var audience []string
	if audClaim, ok := claims["aud"]; ok {
		switch v := audClaim.(type) {
		case string:
			audience = []string{v}
		case []interface{}:
			for _, audVal := range v {
				if audStr, ok := audVal.(string); ok {
					audience = append(audience, audStr)
				}
			}
		}
	}

	// Return the Token struct
	return &Token{
		raw:    token,
		Header: header,
		Claims: claims,
		Sig:    sig,
		Iss:    issuer,
		Exp:    expiration,
		Nbf:    notBefore,
		Aud:    audience,
	}, nil
}

func ValidateJWT(t *Token, key crypto.PublicKey, issuer string, validateAud bool, aud []string) (*Token, error) {

	// JWT Validation Steps (Based on RFC 7519):
	// 1. Split the JWT into its three components: header, payload, and signature.
	//    - Ensure that the JWT is formatted correctly, with exactly three parts separated by periods ('.').
	// 2. Base64 URL-decode the header and payload.
	//    - Ensure that both are valid JSON objects.
	//    - The header should specify the signing algorithm (e.g., "alg": "RS256") and may include a key identifier ("kid").
	// 3. Verify the signature:
	//    a. Reconstruct the signing input by concatenating the Base64-encoded header and payload.
	//    b. Verify the signature using the specified algorithm and the appropriate public key:
	//       - If a `kid` is present in the header, use it to select the correct public key.
	//       - If no `kid` is present, attempt to verify using all available public keys.
	//    c. The signature must be valid and match the signed header and payload.
	// 4. Ensure the signing algorithm used is secure:
	//    - Reject any tokens signed using weak or deprecated algorithms (e.g., "none" or "HS256" for public/private key systems).
	//    - Ensure the token is signed with an algorithm that matches your system's expectations (e.g., RS256, ES256).
	// 5. Validate the claims in the payload:
	//    a. `iss` (issuer): Check that the issuer matches the expected authorization server.
	//    b. `exp` (expiration time): Ensure the token is not expired by comparing the current time with the `exp` claim.
	//    c. `nbf` (not before): Ensure the token is valid at the current time (if the claim is present).
	//    d. `iat` (issued at): Ensure the token was issued at a reasonable time (this is optional, but can help with replay protection).
	//    e. `aud` (audience): If the audience claim is required, ensure it matches the expected audience.

	// Step 1: Split the JWT into header, payload, and signature
	// if no match then don't waste time ...

	header, payload, signature, err := Split(t.raw)
	if err != nil {
		return nil, NewValidationError(ErrTypeParsing, "malformatted token")
	}

	data := header + "." + payload

	if err := VerifySignature(data, signature, t.Header.Alg, key); err != nil {
		return nil, NewValidationError(ErrTypeSignature, "invalid signature")
	}

	// Step 4: Validate claims
	if t.Iss != issuer {
		return nil, NewValidationError(ErrTypeClaims, fmt.Sprintf("invalid issuer: expected %s, got %s", issuer, t.Iss))
	}

	if time.Now().Unix() > t.Exp {
		return nil, NewValidationError(ErrTypeClaims, fmt.Sprintf("token has expired: exp: %d", t.Exp))
	}

	if t.Nbf > 0 && time.Now().Unix() < t.Nbf {
		return nil, NewValidationError(ErrTypeClaims, fmt.Sprintf("token is not valid yet (nbf): nbf: %d, ", t.Nbf))
	}

	if validateAud {
		validAud := false
		for _, a := range t.Aud {
			if slices.Contains(aud, a) {
				validAud = true
				break
			}
		}
		if !validAud {
			return nil, NewValidationError(ErrTypeClaims, fmt.Sprintf("invalid audience: expected one of %v, got %v", aud, t.Aud))
		}
	}

	return t, nil
}

const (
	ErrTypeParsing   = "parsing"
	ErrTypeSignature = "signature"
	ErrTypeClaims    = "claims"
)

type ValidationError struct {
	ErrType string // Type of the error (from defined constants)
	Reason  string // Reason for the error
}

// Error implements the error interface for ValidationError
func (e *ValidationError) Error() string {
	return fmt.Sprintf("[%s] %s", e.ErrType, e.Reason)
}

// Constructor for ValidationError
func NewValidationError(errType, reason string) *ValidationError {
	return &ValidationError{
		ErrType: errType,
		Reason:  reason,
	}
}
