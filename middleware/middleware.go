package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/theadell/authress"
)

// ContextKey defines a custom type for context keys to avoid collisions.
type ContextKey string

// AuthContextKey is the key used to store authentication information in the request context.
var AuthContextKey = ContextKey("x-authenticated")

// TokenExtractor defines a function signature to extract a token from an HTTP request.
type TokenExtractor func(r *http.Request) string

// ContextModifier defines a function signature to modify the request context based on validation results.
type ContextModifier func(ctx context.Context, token *authress.Token, valid bool) context.Context

// BearerTokenExtractor extracts the token from the Authorization header (Bearer token).
func BearerTokenExtractor(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer ")
	}
	return ""
}

// CookieTokenExtractor extracts a token from a cookie.
func CookieTokenExtractor(r *http.Request, cookieName string) string {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return ""
	}
	return cookie.Value
}

// CustomHeaderTokenExtractor extracts a token from a custom HTTP header.
func CustomHeaderTokenExtractor(r *http.Request, headerName string) string {
	return r.Header.Get(headerName)
}

// defaultContextModifier sets "x-authenticated" to true or false in the request context.
func defaultContextModifier(ctx context.Context, Token *authress.Token, valid bool) context.Context {
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

func Enforce(v *authress.Validator, opts ...MiddlewareOption) func(http.Handler) http.Handler {
	mOpts := &middlewareOptions{
		tokenExtractor:  BearerTokenExtractor,
		contextModifier: defaultContextModifier,
	}
	for _, opt := range opts {
		opt(mOpts)
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			token := mOpts.tokenExtractor(r)
			_, err := v.ValidateJWT(token)
			if err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			ctx := mOpts.contextModifier(r.Context(), nil, true)
			r = r.WithContext(ctx)
			next.ServeHTTP(w, r)
		})
	}
}

func AuthenticateAndSetContext(v *authress.Validator, opts ...MiddlewareOption) func(http.Handler) http.Handler {
	mOpts := &middlewareOptions{
		tokenExtractor:  BearerTokenExtractor,
		contextModifier: defaultContextModifier,
	}
	for _, opt := range opts {
		opt(mOpts)
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			token := mOpts.tokenExtractor(r)
			t, err := v.ValidateJWT(token)
			valid := err == nil
			if !valid {
				t = &authress.Token{}
			}
			ctx := mOpts.contextModifier(r.Context(), t, valid)
			r = r.WithContext(ctx)
			next.ServeHTTP(w, r)
		})
	}
}
