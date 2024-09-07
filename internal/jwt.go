package internal

import (
	"crypto/rsa"
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
type JWTPayload struct {
	Exp   int64          `json:"exp"`
	Iat   int64          `json:"iat"`
	Iss   string         `json:"iss"`
	Nonce string         `json:"nonce"`
	Acr   string         `json:"acr"`
	Amr   string         `json:"amr"`
	Azp   string         `json:"azp"`
	Aud   []string       `json:"aud"`
	Extra map[string]any `json:"-"`
}

func (p *JWTPayload) UnmarshalJSON(data []byte) error {

	var temp map[string]any
	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}

	if exp, ok := temp["exp"].(float64); ok {
		p.Exp = int64(exp)
	}
	if iat, ok := temp["iat"].(float64); ok {
		p.Iat = int64(iat)
	}
	if iss, ok := temp["iss"].(string); ok {
		p.Iss = iss
	}
	if nonce, ok := temp["nonce"].(string); ok {
		p.Nonce = nonce
	}
	if acr, ok := temp["acr"].(string); ok {
		p.Acr = acr
	}
	if amr, ok := temp["amr"].(string); ok {
		p.Amr = amr
	}
	if azp, ok := temp["azp"].(string); ok {
		p.Azp = azp
	}
	if aud, ok := temp["aud"].(string); ok {
		p.Aud = []string{aud}
	} else if audSlice, ok := temp["aud"].([]any); ok {
		for _, v := range audSlice {
			if audStr, ok := v.(string); ok {
				p.Aud = append(p.Aud, audStr)
			}
		}
	}

	p.Extra = temp

	return nil
}

func (p *JWTPayload) GetClaim(key string) any {
	if value, ok := p.Extra[key]; ok {
		return value
	}
	return nil
}
func (p *JWTPayload) GetStringClaim(key string) string {
	value := p.GetClaim(key)
	if strValue, ok := value.(string); ok {
		return strValue
	}
	return ""
}
func (p *JWTPayload) GetIntClaim(key string) int {
	value := p.GetClaim(key)
	if floatValue, ok := value.(float64); ok {
		return int(floatValue)
	}
	return 0
}

func (p *JWTPayload) GetStructClaim(key string, out any) error {
	value := p.GetClaim(key)
	if claimMap, ok := value.(map[string]interface{}); ok {
		claimJSON, _ := json.Marshal(claimMap)
		return json.Unmarshal(claimJSON, out)
	}
	return fmt.Errorf("authress: claim not found or not a valid struct")
}

func Split(token string) (string, string, string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", "", "", errors.New("invalid JWT structure")
	}
	return parts[0], parts[1], parts[2], nil
}

func decodeJWTPart[T JWTHeader | JWTPayload](encodedPart string) (*T, error) {
	// Base64 URL-decode the part (either header or payload)
	partBytes, err := base64.RawURLEncoding.DecodeString(encodedPart)
	if err != nil {
		return nil, errors.New("failed to decode part: " + err.Error())
	}

	// Unmarshal the decoded bytes into the provided type T (JWTHeader, JWTPayload, etc.)
	var part T
	if err := json.Unmarshal(partBytes, &part); err != nil {
		return nil, errors.New("failed to unmarshal part: " + err.Error())
	}

	return &part, nil
}

func DecodeJWT(token string) (*JWTHeader, *JWTPayload, error) {
	// Step 1: Split the JWT into header, payload, and signature
	encodedHeader, encodedPayload, _, err := Split(token)
	if err != nil {
		return nil, nil, err
	}

	// Step 2: Decode the header
	header, err := decodeJWTPart[JWTHeader](encodedHeader)
	if err != nil {
		return nil, nil, errors.New("failed to decode JWT header: " + err.Error())
	}

	// Step 3: Decode the payload
	payload, err := decodeJWTPart[JWTPayload](encodedPayload)
	if err != nil {
		return nil, nil, errors.New("failed to decode JWT payload: " + err.Error())
	}

	// Return both header and payload
	return header, payload, nil
}

func ValidateJWT(tokenString string, keys map[string]*rsa.PublicKey, issuer string, validateAud bool, aud []string) (*JWTHeader, *JWTPayload, error) {

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
	header, payload, signature, err := Split(tokenString)
	if err != nil {
		return nil, nil, validationError("parsing", "malformatted token", err.Error())
	}

	// Step 2: Decode the JWT
	jwtHeader, claims, err := DecodeJWT(tokenString)
	if err != nil {
		return nil, nil, validationError("decoding", "malformatted token", err.Error())
	}

	data := header + "." + payload

	// Step 3: Signature verification
	if jwtHeader.Kid != "" {
		key, ok := keys[jwtHeader.Kid]
		if !ok {
			return nil, nil, validationError("signature", "no matching key found for kid", jwtHeader.Kid)
		}
		if err := VerifyRSASignature(data, signature, jwtHeader.Alg, key); err != nil {
			return nil, nil, validationError("signature", "signature verification failed: invalid signature", err.Error())
		}
	} else {
		for _, pubKey := range keys {
			err = VerifyRSASignature(data, jwtHeader.Alg, signature, pubKey)
			if err == nil {
				break
			}
		}
		if err != nil {
			return nil, nil, validationError("signature", "no matching key found for kid", err.Error())
		}
	}

	// Step 4: Validate claims
	if claims.Iss != issuer {
		return nil, nil, validationError("claims", "invalid issuer", fmt.Sprintf("expected %s, got %s", issuer, claims.Iss))
	}

	if time.Now().Unix() > claims.Exp {
		return nil, nil, validationError("claims", "token has expired", fmt.Sprintf("exp: %d, now: %d", claims.Exp, time.Now().Unix()))
	}

	nbf := claims.GetIntClaim("nbf")
	if nbf > 0 && time.Now().Unix() < int64(nbf) {
		return nil, nil, validationError("claims", "token is not valid yet (nbf)", fmt.Sprintf("nbf: %d, now: %d", nbf, time.Now().Unix()))
	}

	if validateAud {
		validAud := false
		for _, a := range claims.Aud {
			if slices.Contains(aud, a) {
				validAud = true
				break
			}
		}
		if !validAud {
			return nil, nil, validationError("claims", "invalid audience", "aud claim did not match expected audience/s")
		}
	}

	return jwtHeader, claims, nil
}

type JWTValidationError struct {
	Message string // Descriptive error message
	Stage   string // Stage where the error occurred (e.g., "parsing", "signature", "claims")
	Detail  string // Additional details about the error (e.g., missing kid, incorrect signature)
}

// Error implements the error interface.
func (e *JWTValidationError) Error() string {
	return fmt.Sprintf("JWT Validation Error at %s stage: %s. Detail: %s", e.Stage, e.Message, e.Detail)
}

// Helper function to create a new JWTValidationError.
func validationError(stage, message, detail string) *JWTValidationError {
	return &JWTValidationError{
		Stage:   stage,
		Message: message,
		Detail:  detail,
	}
}
