package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/theadell/authress"
)

type contextKey string

// AuthContextKey is the key used to store authentication information in the request context.
var AuthContextKey = contextKey("x-authenticated")

// AuthCtx holds information about the authenticated request.
type AuthCtx struct {
	IsAuthenticated bool
	Token           *authress.Token
}

func GetAuthCtx(ctx context.Context) (*AuthCtx, bool) {
	authInfo, ok := ctx.Value(AuthContextKey).(*AuthCtx)
	return authInfo, ok
}

// TokenExtractor extracts a token from the HTTP request (e.g., from a header or cookie).
type TokenExtractor func(r *http.Request) string

// ContextModifier modifies the request context, adding authentication details if the token is valid.
type ContextModifier func(ctx context.Context, token *authress.Token, valid bool) context.Context

// ErrorResponder handles the HTTP response when token validation fails (e.g., sending a 401 Unauthorized).
type ErrorResponder func(w http.ResponseWriter, r *http.Request, err error)

type MiddlewareOption func(*middlewareOptions)

// middlewareOptions holds the token extraction and context modification logic.
type middlewareOptions struct {
	tokenExtractor  TokenExtractor
	contextModifier ContextModifier
	errorResponder  func(w http.ResponseWriter, r *http.Request, err error)
}

// WithContextModifier sets custom JWT extractor from the request context based on authentication.
func WithTokenExtractor(extractor TokenExtractor) MiddlewareOption {
	return func(opts *middlewareOptions) {
		if extractor != nil {
			opts.tokenExtractor = extractor
		}
	}
}

// WithContextModifier sets a custom modifer of the request context
func WithContextModifier(modifier ContextModifier) MiddlewareOption {
	return func(opts *middlewareOptions) {
		if modifier != nil {
			opts.contextModifier = modifier
		}
	}
}

// WithErrorResponder sets custom error response handling
func WithErrorResponder(responder ErrorResponder) MiddlewareOption {
	return func(opts *middlewareOptions) {
		if responder != nil {
			opts.errorResponder = responder
		}
	}
}

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

// defaultErrorResponder sends a 401 Unauthorized response with a message about the invalid token.
func defaultErrorResponder(w http.ResponseWriter, r *http.Request, err error) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusUnauthorized)
	w.Write([]byte(http.StatusText(http.StatusUnauthorized)))
}

// defaultContextModifier sets "x-authenticated" to true or false in the request context.
func defaultContextModifier(ctx context.Context, token *authress.Token, valid bool) context.Context {
	authInfo := &AuthCtx{
		IsAuthenticated: valid,
		Token:           token,
	}
	return context.WithValue(ctx, AuthContextKey, authInfo)
}
