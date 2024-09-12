package authress

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"
)

// Claims represent JWT data. Registered claims (RFC 7519) and common OIDC claims are available as fields.
// Missing claims default to zero values
// Additional claims can be accessed lazily with [Claims.GetClaim].
type Claims struct {

	// Audience (aud) is the token's intended recipients.
	Audience audience `json:"aud"`

	// Issuer (iss) is the entity that issued the token.
	Issuer string `json:"iss"`

	// Subject (sub) is the principal the token is issued for.
	Subject string `json:"sub"`

	// ExpiresAt (exp) is the token's expiration time.
	ExpiresAt int64 `json:"exp"`

	// IssuedAt (iat) is when the token was issued.
	IssuedAt int64 `json:"iat"`

	// NotBefore (nbf) indicates when the token becomes valid.
	NotBefore int64 `json:"nbf"`

	// optional OIDC claim, zero value if absent
	Name string `json:"name"`

	// optional OIDC claim, zero value if absent
	GivenName string `json:"given_name"`

	// optional OIDC claim, zero value if absent
	FamilyName string `json:"family_name"`

	// optional OIDC claim, zero value if absent
	Email string `json:"email"`

	// optional OIDC claim, zero value if absent
	EmailVerified bool `json:"email_verified"`

	// optional OIDC claim, zero value if absent
	Picture string `json:"picture"`

	// optional OIDC claim, zero value if absent
	Scope string `json:"scope"`

	rawPayload []byte

	rawClaims map[string]any
}

// GetClaim returns a calim by its key
func (c *Claims) GetClaim(key string) (any, bool) {
	if c.rawClaims == nil {
		var allClaims map[string]any
		if err := json.Unmarshal(c.rawPayload, &allClaims); err != nil {
			// should never occur
			return nil, false
		}
		c.rawClaims = allClaims
	}
	value, exists := c.rawClaims[key]
	return value, exists
}

// GetStringClaim retrieves the value of a claim by its key as a string.
// If the claim is missing or not a string, an empty string is returned.
func (c *Claims) GetStringClaim(key string) string {
	if value, ok := c.GetClaim(key); ok {
		if str, ok := value.(string); ok {
			return str
		}
	}
	return ""
}

// GetIntClaim retrieves the value of a claim by its key as a int64.
// If the claim is missing or not numeric, zero returned.
func (c *Claims) GetIntClaim(key string) int64 {
	if value, ok := c.GetClaim(key); ok {
		switch v := value.(type) {
		case float64:
			return int64(v)
		case int64:
			return v
		}
	}
	return 0
}

// GetClaimAs retrieves the claim by `key` and unmarshals it into `v`, which must be
// a non-nil pointer. It uses reflection to dynamically map the claim to the provided type.
//
// This involves unmarshaling the raw JSON, which can be costly.
//
// Returns an error if the key is empty or if `v` is not a valid pointer.
func (c *Claims) GetClaimAs(key string, v interface{}) error {

	if key == "" {
		return fmt.Errorf("GetClaimAs: key cannot be empty")
	}
	vValue := reflect.ValueOf(v)
	if vValue.Kind() != reflect.Ptr || vValue.IsNil() {
		return fmt.Errorf("GetClaimAs: provided variable must be a non-nil pointer")
	}

	tempStruct := reflect.New(reflect.StructOf([]reflect.StructField{
		{
			Name: "Field",
			Type: reflect.TypeOf(v).Elem(),
			Tag:  reflect.StructTag(fmt.Sprintf(`json:"%s"`, key)),
		},
	})).Interface()

	if err := json.Unmarshal(c.rawPayload, &tempStruct); err != nil {
		return fmt.Errorf("failed to unmarshal claims: %w", err)
	}

	fieldValue := reflect.ValueOf(tempStruct).Elem().Field(0).Interface()

	if reflect.ValueOf(v).Kind() == reflect.Ptr && reflect.ValueOf(v).Elem().CanSet() {
		reflect.ValueOf(v).Elem().Set(reflect.ValueOf(fieldValue))
	} else {
		return fmt.Errorf("provided variable is not a settable pointer")
	}

	return nil
}

// ExpiresAtTime returns the `exp` time as time.Time
func (c *Claims) ExpiresAtTime() time.Time {
	return time.Unix(c.ExpiresAt, 0)
}

// IssuedAtTime returns the token's `iat` time as a time.Time
func (c *Claims) IssuedAtTime() time.Time {
	return time.Unix(c.IssuedAt, 0)
}

// NotBeforeTime returns the token's `nbf` time as a time.Time
func (c *Claims) NotBeforeTime() time.Time {
	return time.Unix(c.NotBefore, 0)
}

// Scopes returns the token's scopes
func (c *Claims) Scopes() []string {
	if c.Scope == "" {
		return []string{}
	}
	return strings.Split(c.Scope, " ")
}

type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return fmt.Errorf("%w: audience format is invalid", ErrInvalidAudience)
	}

	switch v := v.(type) {
	case string:
		*a = audience{v}
		return nil
	case []any:
		aud := make(audience, len(v))
		for i := range v {
			v, ok := v[i].(string)
			if !ok {
				return fmt.Errorf("%w: audience format is invalid", ErrInvalidAudience)
			}
			aud[i] = v
		}
		*a = aud
		return nil
	default:
		return fmt.Errorf("%w: audience format is invalid", ErrInvalidAudience)
	}
}

func (c *Claims) hasAudience(audiences ...string) bool {
	for _, aud := range c.Audience {
		for _, audience := range audiences {
			if equal(aud, audience) {
				return true
			}
		}
	}
	return false
}
