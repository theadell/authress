package middleware

import (
	"net/http"

	"github.com/theadell/authress"
)

// RequireAuthJWT requires that a valid JWT is present in the request.
// If the JWT is invalid or missing, the request is rejected with HTTP 401 Unauthorized.
// If the JWT is valid, the parsed token is injected into the request context.
//
// The JSON Web Token is extracted from the `Authorization` header using the Bearer scheme by default.
// You can customize the token extraction method using the [WithTokenExtractor] option, such as extracting the token from a cookie or a custom header.
//
// if the JWT is valid, the request context is modified to include the parsed token and a flag indicating whether the request is authenticated.
// See the [WithContextModifier] option
//
// If the token is invalid or missing, the middleware responds with a 401 status and a default "Unauthorized" message.
// The error response can be customized using [WithErrorResponder] option.
//
// Example Usage:
//
//	requireJWT := RequireAuthJWT(validator)
//	http.Handle("/secure", requireJWT(http.HandlerFunc(secureHandler)))
//	http.ListenAndServe(":8080", nil)
//
//	// Custom token extraction from a cookie and custom error response
//	requireJWT := RequireAuthJWT(validator,
//	    WithTokenExtractor(func(r *http.Request) string {
//	        cookie, err := r.Cookie("token")
//	        if err != nil {
//	            return ""
//	        }
//	        return cookie.Value
//	    }),
//	    WithErrorResponder(func(w http.ResponseWriter, r *http.Request, err error) {
//	        http.Error(w, "Custom unauthorized message", http.StatusUnauthorized)
//	    }))
func RequireAuthJWT(v *authress.Validator, opts ...MiddlewareOption) func(http.Handler) http.Handler {
	mOpts := &middlewareOptions{
		tokenExtractor:  BearerTokenExtractor,
		contextModifier: defaultContextModifier,
		errorResponder:  defaultErrorResponder,
	}
	for _, opt := range opts {
		opt(mOpts)
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			token := mOpts.tokenExtractor(r)
			t, err := v.ValidateJWT(token)
			if err != nil {
				mOpts.errorResponder(w, r, err)
				return
			}
			r = r.WithContext(mOpts.contextModifier(r.Context(), t, true))
			next.ServeHTTP(w, r)
		})
	}
}

// SetAuthContextJWT validates the JWT and injects the parsed token into the request context WITHOUT enforcing authentication.
// The Authentication decision is left to downstream middleware / handlers.
//
// The JWT is extracted from the `Authorization` header using the Bearer scheme by default, See [WithTokenExtractor] option.
// You can modify how the context is updated using the [WithContextModifier] option.
//
// Example Usage:
//
//	chain := alice.New(setAuthContextJWT, setAuthContextLDAP, enforceAuth, authorize).Then(http.HandlerFunc(secureHandler))
//	http.Handle("/secure", chain)
//	http.ListenAndServe(":8080", nil)
func SetAuthContextJWT(v *authress.Validator, opts ...MiddlewareOption) func(http.Handler) http.Handler {
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
			r = r.WithContext(mOpts.contextModifier(r.Context(), t, true))
			next.ServeHTTP(w, r)
		})
	}
}

// RequireAuthWithIntrospection requires a valid JWT by token introspection as defined by [RFC 7662].
// Inrospection introduces network latency as it requires an HTTP roundtrip. useful for critical endpoints
// where ensuring that the token has not been revoked is important. In Most cases [RequireAuthJWT] middlware should be preferred
//
// Example Usage:
//
//	requireAuth := RequireAuthWithIntrospection(introspectionValidator)
//	http.Handle("/important", requireAuth(http.HandlerFunc(importantHandler)))
//
//	http.ListenAndServe(":8080", nil)
//
// [RFC 7662]: https://tools.ietf.org/html/rfc7662
func RequireAuthWithIntrospection(v *authress.Validator, opts ...MiddlewareOption) func(http.Handler) http.Handler {
	mOpts := &middlewareOptions{
		tokenExtractor:  BearerTokenExtractor,
		contextModifier: defaultContextModifier,
		errorResponder:  defaultErrorResponder,
	}
	for _, opt := range opts {
		opt(mOpts)
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := mOpts.tokenExtractor(r)
			t, parseErr := v.Parse(token)
			valid, err := v.IntrospectToken(r.Context(), token)
			if !valid || err != nil || parseErr != nil {
				mOpts.errorResponder(w, r, err)
				return
			}
			r = r.WithContext(mOpts.contextModifier(r.Context(), t, true))
			next.ServeHTTP(w, r)
		})
	}
}

// SetAuthCtxWithIntrospection validates the token via introspection (RFC 7662) but DOES NOT ENFORCE authentication.
// It adds the token and its status to the context for downstream use.
//
// Example:
//
//	v, err := authress.NewValidator(
//			authress.WithAuthServerDiscovery(kcDiscoveryUrl),
//			authress.WithIntrospection(clientID, clientSecret))
//	if err != nil {
//		panic(err) // handle error
//	}
//	setAuthCtx := SetAuthCtxWithIntrospection(v)
//	chain := alice.New(setAuthCtx, setContextLDAP, enforceAuth, authorize).Then(http.HandlerFunc(secureHandler))
//	http.Handle("/endpoint", chain)
//
//	http.ListenAndServe(":8080", nil)
func SetAuthCtxhWithIntrospection(v *authress.Validator, opts ...MiddlewareOption) func(http.Handler) http.Handler {
	mOpts := &middlewareOptions{
		tokenExtractor:  BearerTokenExtractor,
		contextModifier: defaultContextModifier,
		errorResponder:  defaultErrorResponder,
	}
	for _, opt := range opts {
		opt(mOpts)
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := mOpts.tokenExtractor(r)
			t, parseErr := v.Parse(token)
			valid, err := v.IntrospectToken(r.Context(), token)
			if !valid || err != nil || parseErr != nil {
				t = &authress.Token{}
			}
			r = r.WithContext(mOpts.contextModifier(r.Context(), t, true))
			next.ServeHTTP(w, r)
		})
	}
}
