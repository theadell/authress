# Authress

Authress is a lightweight Go package for OAuth 2.0 / OpenID Connect (OIDC) **resource server** *token* authentication using JWT [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519) and [Token Introspection](https://datatracker.ietf.org/doc/html/rfc7662). It lets you verify tokens issued by an authorization server (like Auth0, Keycloak, etc.) and used against your API (resource server). 

### Features
- [OAuth2/OIDC Discovery](https://datatracker.ietf.org/doc/html/rfc8414): Automatic fetching and handling of [JWKS](https://auth0.com/docs/secure/tokens/json-web-tokens/json-web-key-sets) based on auth server discovery. 
- JWT Validation and Parsing: 
- Token Introspection: Supports token introspection for cases where you need to verify token status directly with the authorization server.
- Middleware: Provides middleware for validating JWTs in HTTP requests.

### TODO:  
- Token Rotation Support: Handling automatic key rotation from the authorization server.
- Additional Signing Algorithms: Currently, only RSA is supported.

### Installation
```sh
go get https://github.com/theadell/authress
```

### Examples

#### Middleware 

```go 
package main

import (
	"log"
	"net/http"

	"github.com/justinas/alice"        
	"github.com/theadell/authress"
	"github.com/theadell/authress/middleware"
)

func main() {

	validator, err := authress.NewValidator(
		authress.WithAuthServerDiscovery("https://example.com/.well-known/openid-configuration"),
		authress.WithIntrospection("clientID", "clientSecret"))
	if err != nil {
		log.Fatalf("Failed to create validator: %v", err)
	}

	// Enforce JWT validation 
	requireJWT := authress.RequireAuthJWT(validator)
	http.Handle("/secure", requireJWT(http.HandlerFunc(jwtSecureHandler)))

	// Enforce introspection validation
	requireIntrospection := authress.RequireAuthWithIntrospection(validator)
	http.Handle("/important", requireIntrospection(http.HandlerFunc(introspectSecureHandler)))

	// Inject JWT into context without enforcing authentication (delegated to down-stream middleware)
	setAuthContext := authress.SetAuthContextJWT(validator)
	chain := alice.New(setAuthCtx, setContextLDAP, enforceAuth, authorize).Then(http.HandlerFunc(secureHandler))
	http.Handle("/another-route", chain)

	log.Fatal(http.ListenAndServe(":8080", nil))
}
```
#### Customize Middlware 

```go
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/theadell/authress"
	"github.com/theadell/authress/middleware"
)

// Custom Token Extractor: Extract JWT from a custom header (or cookie, etc.)
func customTokenExtractor(r *http.Request) string {
	cookie, err := r.Cookie("token")
	if err != nil {
		return "" 
	}
	return cookie.Value
}

// Custom Context Modifier: Inject custom values into the request context 
func customContextModifier(ctx context.Context, token *authress.Token) context.Context {
	return context.WithValue(ctx, "userRole", token.GetStringClain("role"))
}

// Custom Error Responder: Customize the error response when validation fails
func customErrorResponder(w http.ResponseWriter, r *http.Request, err error) {
	http.Error(w, "Custom Unauthorized: "+err.Error(), http.StatusUnauthorized)
}

func main() {
//...

	requireJWT := authress.RequireAuthJWT(
		validator,
		authress.WithTokenExtractor(customTokenExtractor),       
		authress.WithContextModifier(customContextModifier),     
		authress.WithErrorResponder(customErrorResponder),       
	)

	http.Handle("/secure", requireJWT(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// ...
	})))

	log.Fatal(http.ListenAndServe(":8080", nil))
}

```
#### Validation And parsing 
You can also use the validator directly 

```go
package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/theadell/authress"
)

func main() {
	// Create a Validator using OAuth2/OIDC discovery
	validator, err := authress.NewValidator(
		authress.WithAuthServerDiscovery("https://idp.com/.well-known/openid-configuration"))
	if err != nil {
		log.Fatalf("Failed to create validator: %v", err)
	}

	http.HandleFunc("/secure", func(w http.ResponseWriter, r *http.Request) {
		tokenString := extractToken(r)

		token, err := validator.ValidateJWT(tokenString)
		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}
        // do sth with the token 
        user, err := db.GetUserBySubject(token.Sub())
		// ... 
	})

    http.HandleFunc("/parse", func(w http.ResponseWriter, r *http.Request) {
		tokenString := extractToken(r)

		token, err := validator.Parse(tokenString)
		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}
        // do sth with the token 
        role := token.GetStringClaim("role")
        iss := token.Iss()
        sub := token.Sub()
		// ... 
	})
	log.Fatal(http.ListenAndServe(":8080", nil))
}

```