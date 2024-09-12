# Authress

Authress is a lightweight Go package for OAuth 2.0 / OpenID Connect (OIDC) **resource server** *token* authentication using JWT [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519) and [Token Introspection](https://datatracker.ietf.org/doc/html/rfc7662). It lets you verify tokens issued by an authorization server (like Auth0, Keycloak, etc.) and used against your API (resource server). 

### Features
- [OAuth2/OIDC Discovery](https://datatracker.ietf.org/doc/html/rfc8414): Automatic fetching and handling of [JWKS](https://auth0.com/docs/secure/tokens/json-web-tokens/json-web-key-sets) based on auth server discovery. 
- JWT Validation and Parsing: 
- Token Introspection: Supports token introspection for cases where you need to verify token status directly with the authorization server.
- Middleware: Provides middleware for validating JWTs in HTTP requests.


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
	"os"

	"github.com/justinas/alice"        
	"github.com/theadell/authress"
)

func main() {

	IdpURL := "https://idp.com/.well-known/openid-configuration"

	validator, err := authress.New(
		authress.WithDiscovery(IdpURL),
		authress.WithIntrospection("clientID", "clientSecret"))
	if err != nil {
		log.Fatalf("Failed to create validator: %v", err)
	}

	// Enforce JWT validation 
	requireJWT := authress.RequireAuthJWT(validator)
	http.Handle("/secure", requireJWT(http.HandlerFunc(handler1)))

	// Enforce introspection validation
	requireIntrospection := authress.RequireAuthWithIntrospection(validator)
	http.Handle("/important", requireIntrospection(http.HandlerFunc(handler2)))

	// Inject JWT into context without enforcing authentication
	setAuthContext := authress.SetAuthContextJWT(validator)
	chain := alice.New(setAuthCtx, setContextLDAP, enforceAuth, authorize).
		Then(http.HandlerFunc(handler3))
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
)

// Custom Token Extractor: Extract JWT from a custom header (or cookie, etc.)
func myTokenExtractor(r *http.Request) string {
	cookie, err := r.Cookie("token")
	if err != nil {
		return "" 
	}
	return cookie.Value
}

// Custom Context Modifier: Inject custom values into the request context 
func myContextModifier(ctx context.Context, token *authress.Token) context.Context {
	return context.WithValue(ctx, "userRole", token.GetStringClain("role"))
}

// Custom Error Responder: Customize the error response when validation fails
func myErrorResponder(w http.ResponseWriter, r *http.Request, err error) {
	http.Error(w, "Custom Unauthorized: "+err.Error(), http.StatusUnauthorized)
}

func main() {
//...

	requireJWT := authress.RequireAuthJWT(
		validator,
		authress.WithTokenExtractor(myTokenExtractor),       
		authress.WithContextModifier(myContextModifier),     
		authress.WithErrorResponder(myErrorResponder),       
	)

	http.Handle("/secure", requireJWT(http.HandlerFunc(myHandler))

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
	validator, err := authress.New(
		authress.WithAuthServerDiscovery(IdpUrl))
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
        email := token.Email
		pic := token.Picture
		var claim MyCustomClaimType
		token.GetClaimAs("MyCustomClaimKey", &claim)
		// ... 
	})
	log.Fatal(http.ListenAndServe(":8080", nil))
}

```

#### Using Your Own Cryptographic Keys
You can provide custom metadata and keys to the validator instead of relying on OAuth2/OIDC discovery.

**Custom Metadata**
To use your own OAuth2 server metadata, pass it via WithMetadata:
```Go
metadata := &authress.OAuth2ServerMetadata{
    Issuer: "https://your-issuer.com",
    // other metadata fields
}
validator, _ := authress.New(authress.WithMetadata(metadata))
```
**Custom JWKS** 
```Go
type MyJWKSStore struct{}

func (s *MyJWKSStore) GetKey(ctx context.Context, kid string) (crypto.PublicKey, error) {
    // Retrieve key by 'kid'
    return myKey, nil
}

validator, _ := authress.New(authress.WithJWKS(&MyJWKSStore{}), authress.WithMetadata(metadata))
```