package authress

import (
	"context"
	"net/http"
	"strings"
)

// ContextKey defines a custom type for context keys to avoid collisions.
type ContextKey string

// AuthContextKey is the key used to store authentication information in the request context.
var AuthContextKey = ContextKey("x-authenticated")

// TokenExtractor defines a function signature to extract a token from an HTTP request.
type TokenExtractor func(r *http.Request) string

// ContextModifier defines a function signature to modify the request context based on validation results.
type ContextModifier func(ctx context.Context, claims *map[string]string, valid bool) context.Context

// BearerTokenExtractor extracts the token from the Authorization header (Bearer token).
func BearerTokenExtractor(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer ")
	}
	return ""
}

// DefaultContextModifier sets "x-authenticated" to true or false in the request context.
func DefaultContextModifier(ctx context.Context, claims *map[string]string, valid bool) context.Context {
	if valid {
		ctx = context.WithValue(ctx, AuthContextKey, true)
	} else {
		ctx = context.WithValue(ctx, AuthContextKey, false)
	}
	return ctx
}

type MiddlewareOption func(*middlewareOptions)

// middlewareOptions holds the token extraction and context modification logic.
type middlewareOptions struct {
	tokenExtractor  TokenExtractor
	contextModifier ContextModifier
}

func WithTokenExtractor(extractor TokenExtractor) MiddlewareOption {
	return func(opts *middlewareOptions) {
		opts.tokenExtractor = extractor
	}
}

// WithContextModifier allows customization of context modification in middleware.
func WithContextModifier(modifier ContextModifier) MiddlewareOption {
	return func(opts *middlewareOptions) {
		opts.contextModifier = modifier
	}
}
