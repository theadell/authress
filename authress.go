package authress

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/theadell/authress/internal"
	"golang.org/x/oauth2"
)

type Validator struct {
	config *config
}

// Parse parses and returns the JWT Token or error if the token is not strucrually valid JWT
func (v *Validator) Parse(tokenString string) (*Token, error) {
	t, err := parse([]byte(tokenString))
	if err != nil {
		return nil, err
	}
	return t, nil
}

// ValidateJWT checks if the given JWT is valid by verifying its signature and standard claims.
// Returns a Token object on success or an error if validation fails.
func (v *Validator) ValidateJWT(tokenString string) (*Token, error) {
	token, err := parse([]byte(tokenString))
	if err != nil {
		return nil, fmt.Errorf("malformatted or invalid JWT")
	}
	key, err := v.config.set.GetKey(context.TODO(), token.header.Kid)
	if err != nil {
		return nil, fmt.Errorf("invalid token: no key found in JWKS for key id")
	}
	t, err := validateJWT(token, key, v.config.AuthServerMetadata.Issuer, v.config.ValidateAudience, v.config.Audience)
	if err != nil {
		return nil, err
	}
	return t, nil
}

// IntrospectToken checks if the provided token is active by querying the introspection endpoint according to RFC 7662.
// Most users will prefer using [Validator.ValidateJWT] for local validation to avoid the network latency of introspection.
// Introspection is useful for opaque tokens or when you need to confirm if a token has been revoked.
func (v *Validator) IntrospectToken(ctx context.Context, token string) (bool, error) {
	if !v.config.EnableIntrospection {
		return false, fmt.Errorf("authress: introspection is not enabled")
	}

	req := internal.IntrospectionRequest{
		Token:        token,
		ClientID:     v.config.clientId,
		ClientSecret: v.config.clientSecret,
	}

	resp, err := internal.IntrospectToken(v.config.HTTPClient, v.config.AuthServerMetadata.IntrospectionEndpoint, req)
	if err != nil {
		return false, err
	}
	return resp.Active, nil
}

// ClientEndpoint return `x/oauth2` client Endpoint
func (v *Validator) ClientEndpoint() oauth2.Endpoint {
	return v.config.AuthServerMetadata.Endpoint()
}

type config struct {
	AuthServerDiscoveryURL string
	HTTPClient             *http.Client
	EnableIntrospection    bool
	ValidateAudience       bool
	Audience               []string
	ValidateRoles          bool
	RolesClaim             string
	AuthServerMetadata     *OAuth2ServerMetadata
	keys                   map[string]*rsa.PublicKey
	clientId               string
	clientSecret           string
	set                    JWKSStore
}

type Option func(*config)

func New(options ...Option) (*Validator, error) {
	validator := &Validator{
		config: &config{
			HTTPClient: &http.Client{
				Timeout: 10 * time.Second,
			},
			keys: make(map[string]*rsa.PublicKey),
		},
	}

	for _, opt := range options {
		opt(validator.config)
	}

	if validator.config.AuthServerDiscoveryURL == "" && validator.config.AuthServerMetadata == nil {
		return nil, errors.New("invalid config: either discovery URL or metadata and keys must be provided")
	}

	if validator.config.AuthServerDiscoveryURL != "" && validator.config.AuthServerMetadata == nil {
		metadata, jwks, err := discoverOAuth2ServerMetadata(validator.config.HTTPClient, validator.config.AuthServerDiscoveryURL)
		if err != nil {
			return nil, fmt.Errorf("discovery error: failed to discover authorization server metadata: %w", err)
		}

		validator.config.AuthServerMetadata = metadata
		validator.config.set = &inMemoryStore{set: jwks}
	}

	if validator.config.EnableIntrospection && validator.config.AuthServerMetadata.IntrospectionEndpoint == "" {
		return nil, errors.New("invalid config: introspection is enabled but the authorization server does not support it")
	}

	return validator, nil
}

// WithHTTPClient sets a custom HTTP client for fetching JWKS and introspection.
func WithHTTPClient(client *http.Client) Option {
	return func(c *config) {
		c.HTTPClient = client
	}
}

// WithIntrospection enables token introspection.
func WithIntrospection(clientId, clientSecret string) Option {
	return func(c *config) {
		c.EnableIntrospection = true
		c.clientId = clientId
		c.clientSecret = clientSecret
	}
}

// WithAudienceValidation enables or disables audience validation and sets the expected audience.
func WithAudienceValidation(audience ...string) Option {
	return func(c *config) {
		c.ValidateAudience = true
		c.Audience = audience
	}
}

func WithDiscovery(discoveryUrl string) Option {
	return func(c *config) {
		c.AuthServerDiscoveryURL = discoveryUrl
	}
}

func WithMetadata(metadata *OAuth2ServerMetadata) Option {
	return func(c *config) {
		c.AuthServerMetadata = metadata
	}
}
func WithJWKS(jwks JWKSStore) Option {
	return func(c *config) {
		c.set = jwks
	}
}
