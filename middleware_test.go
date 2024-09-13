package authress

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/theadell/authress/internal"
)

func TestRequireAuthJWT(t *testing.T) {

	v := newValidator(t)

	mw := RequireAuthJWT(v)
	ts := httptest.NewServer(mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })))
	defer ts.Close()
	client := ts.Client()

	validToken, expiredToken, tamperedToken := generateTestTokens(t)

	type testCase struct {
		Name               string
		Token              string
		ExpectedStatusCode int
	}

	var cases = []testCase{
		{
			Name:               "unauthenticated request",
			Token:              "",
			ExpectedStatusCode: http.StatusUnauthorized,
		},
		{
			Name:               "authenticated request",
			Token:              validToken,
			ExpectedStatusCode: http.StatusOK,
		},
		{
			Name:               "authenticated request with expired token",
			Token:              expiredToken,
			ExpectedStatusCode: http.StatusUnauthorized,
		},
		{
			Name:               "authenticated request with tampered token",
			Token:              tamperedToken,
			ExpectedStatusCode: http.StatusUnauthorized,
		},
	}
	for _, tc := range cases {
		req, err := http.NewRequest("GET", ts.URL, nil)
		if err != nil {
			t.Fatalf("NewRequest() = %v; but expected no error", err)
		}
		req.Header.Set("Authorization", "Bearer "+tc.Token)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("failed to send request %v", err)
		}
		defer resp.Body.Close()
		if got, want := resp.StatusCode, tc.ExpectedStatusCode; got != want {
			t.Errorf("RequireAuthJWT: got %d; want %d", got, want)
		}
	}

}

func TestRequireAuthJWTWithCustomTokenExtractor(t *testing.T) {
	v := newValidator(t)

	mw := RequireAuthJWT(v, WithTokenExtractor(func(r *http.Request) string {
		cookie, err := r.Cookie("session")
		if err != nil {
			return ""
		}
		return cookie.Value
	}))
	ts := httptest.NewServer(mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })))
	defer ts.Close()
	client := ts.Client()

	validToken, _, _ := generateTestTokens(t)

	req, err := http.NewRequest("GET", ts.URL, nil)
	if err != nil {
		t.Fatalf("NewRequest() = %v; expected no error", err)
	}
	req.AddCookie(&http.Cookie{
		Name:  "session",
		Value: validToken,
	})

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	if got, want := resp.StatusCode, http.StatusOK; got != want {
		t.Errorf("SetAuthContextJWT: got %d; want %d", got, want)
	}

}

func TestRequireAuthJWTWithCustomErrResponder(t *testing.T) {
	v := newValidator(t)

	mw := RequireAuthJWT(v, WithErrorResponder(func(w http.ResponseWriter, r *http.Request, err error) {
		w.WriteHeader(http.StatusForbidden)
	}))
	ts := httptest.NewServer(mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })))
	defer ts.Close()
	client := ts.Client()

	validToken, expiredToken, _ := generateTestTokens(t)

	var cases = []struct {
		Name               string
		Token              string
		ExpectedStatusCode int
	}{
		{
			Name:               "authenticated request",
			Token:              validToken,
			ExpectedStatusCode: http.StatusOK,
		},
		{
			Name:               "authenticated request with expired token",
			Token:              expiredToken,
			ExpectedStatusCode: http.StatusForbidden,
		},
	}
	for _, tc := range cases {
		req, err := http.NewRequest("GET", ts.URL, nil)
		if err != nil {
			t.Fatalf("NewRequest() = %v; but expected no error", err)

		}
		req.Header.Set("Authorization", "Bearer "+tc.Token)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("failed to send request %v", err)
		}
		defer resp.Body.Close()
		if got, want := resp.StatusCode, tc.ExpectedStatusCode; got != want {
			t.Errorf("RequireAuthJWT: got %d; want %d", got, want)
		}
	}

}

func TestSetAuthContextJWT(t *testing.T) {
	// Assuming generateTestTokens exists and generates tokens
	validToken, expiredToken, tamperedToken := generateTestTokens(t)

	// Set up the Validator and middleware
	v, err := New(WithJWKS(newTestStore(RSAPubKey)), WithMetadata(&OAuth2ServerMetadata{Issuer: "idp.authress.com"}))
	if err != nil {
		t.Fatalf("New() = %v; but expected no error", err)
	}

	// Middleware under test
	mwSetAuthContext := SetAuthContextJWT(v)

	// Set up the test server with SetAuthContextJWT
	ts := httptest.NewServer(mwSetAuthContext(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authCtx, ok := GetAuthCtx(r.Context())
		if !ok {
			t.Errorf("context not set")
		}
		if !authCtx.IsAuthenticated {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	})))
	defer ts.Close()

	client := ts.Client()

	// Define test cases
	type testCase struct {
		Name               string
		Token              string
		ExpectedStatusCode int
		IsAuthenticated    bool
	}

	// Test cases for valid, expired, and tampered tokens
	var cases = []testCase{
		{
			Name:               "unauthenticated request",
			Token:              "",
			ExpectedStatusCode: http.StatusUnauthorized,
			IsAuthenticated:    false,
		},
		{
			Name:               "authenticated request",
			Token:              validToken,
			ExpectedStatusCode: http.StatusOK,
			IsAuthenticated:    true,
		},
		{
			Name:               "authenticated request with expired token",
			Token:              expiredToken,
			ExpectedStatusCode: http.StatusUnauthorized,
			IsAuthenticated:    false,
		},
		{
			Name:               "authenticated request with tampered token",
			Token:              tamperedToken,
			ExpectedStatusCode: http.StatusUnauthorized,
			IsAuthenticated:    false,
		},
	}

	// Iterate over test cases
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			req, err := http.NewRequest("GET", ts.URL, nil)
			if err != nil {
				t.Fatalf("NewRequest() = %v; expected no error", err)
			}
			if tc.Token != "" {
				req.Header.Set("Authorization", "Bearer "+tc.Token)
			}

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("failed to send request: %v", err)
			}
			defer resp.Body.Close()

			if got, want := resp.StatusCode, tc.ExpectedStatusCode; got != want {
				t.Errorf("SetAuthContextJWT: got %d; want %d", got, want)
			}
		})
	}
}

func TestSetAuthContextJWTWithCustomModifier(t *testing.T) {
	v := newValidator(t)

	var roleKey contextKey = "role"
	mw := SetAuthContextJWT(v, WithTokenExtractor(CookieTokenExtractor("session")), WithContextModifier(func(ctx context.Context, token *Token, valid bool) context.Context {
		return context.WithValue(ctx, roleKey, "user")

	}))
	ts := httptest.NewServer(mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if role, ok := r.Context().Value(roleKey).(string); !ok || role != "user" {
			w.WriteHeader(http.StatusUnauthorized)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	})))
	defer ts.Close()
	client := ts.Client()

	validToken, _, _ := generateTestTokens(t)

	req, err := http.NewRequest("GET", ts.URL, nil)
	if err != nil {
		t.Fatalf("NewRequest() = %v; expected no error", err)
	}
	req.AddCookie(&http.Cookie{
		Name:  "session",
		Value: validToken,
	})

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	if got, want := resp.StatusCode, http.StatusOK; got != want {
		t.Errorf("SetAuthContextJWT: got %d; want %d", got, want)
	}

}

func TestIntrospectToken(t *testing.T) {
	introspectHandler := func(w http.ResponseWriter, r *http.Request) {
		token := r.FormValue("token")
		switch token {
		case "valid-token":
			resp := internal.IntrospectionResponse{
				Active:    true,
				ClientID:  "client123",
				Username:  "user123",
				Scope:     "read",
				TokenType: "Bearer",
				Exp:       time.Now().Add(1 * time.Hour).Unix(),
				Iss:       "idp.authress.com",
				Sub:       "1234",
			}
			json.NewEncoder(w).Encode(resp)
		case "invalid-token":
			resp := internal.IntrospectionResponse{
				Active: false,
			}
			json.NewEncoder(w).Encode(resp)
		case "malformed-token":
			w.Write([]byte(`{"invalid_json":`))
		default:
			w.WriteHeader(http.StatusUnauthorized)
		}
	}

	introspectionMux := http.NewServeMux()
	introspectionMux.HandleFunc("/introspect", introspectHandler)
	introspectionServer := httptest.NewServer(introspectionMux)
	defer introspectionServer.Close()

	middlewareMux := http.NewServeMux()

	v := newValidator(t, WithMetadata(&OAuth2ServerMetadata{
		Issuer:                "idp.authress.com",
		IntrospectionEndpoint: introspectionServer.URL + "/introspect",
	}), WithIntrospection("test", "secret"), WithHTTPClient(introspectionServer.Client()))

	mwRequireAuth := RequireAuthWithIntrospection(v, WithErrorResponder(func(w http.ResponseWriter, r *http.Request, err error) {
		w.WriteHeader(http.StatusUnauthorized)
	}))

	mwSetAuthCtx := SetAuthCtxhWithIntrospection(v)

	middlewareMux.Handle("/protected", mwRequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Authorized"))
	})))

	middlewareMux.Handle("/context-protected", mwSetAuthCtx(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authCtx, ok := GetAuthCtx(r.Context())
		if !ok || !authCtx.IsAuthenticated {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Context Set"))
	})))

	middlewareServer := httptest.NewServer(middlewareMux)
	defer middlewareServer.Close()

	client := middlewareServer.Client()

	type testCase struct {
		Name               string
		Token              string
		ExpectedStatusCode int
		Endpoint           string
	}

	// Define test cases for both middlewares
	testCases := []testCase{
		{
			Name:               "Valid token should return 200 (RequireAuthWithIntrospection)",
			Token:              "valid-token",
			ExpectedStatusCode: http.StatusOK,
			Endpoint:           "/protected",
		},
		{
			Name:               "Invalid token should return 401 (RequireAuthWithIntrospection)",
			Token:              "invalid-token",
			ExpectedStatusCode: http.StatusUnauthorized,
			Endpoint:           "/protected",
		},
		{
			Name:               "Malformed introspection response should return 401 (RequireAuthWithIntrospection)",
			Token:              "malformed-token",
			ExpectedStatusCode: http.StatusUnauthorized,
			Endpoint:           "/protected",
		},
		{
			Name:               "Valid token should return 200 (SetAuthCtxhWithIntrospection)",
			Token:              "valid-token",
			ExpectedStatusCode: http.StatusOK,
			Endpoint:           "/context-protected",
		},
		{
			Name:               "Invalid token should return 401 (SetAuthCtxhWithIntrospection)",
			Token:              "invalid-token",
			ExpectedStatusCode: http.StatusUnauthorized,
			Endpoint:           "/context-protected",
		},
		{
			Name:               "Malformed introspection response should return 401 (SetAuthCtxhWithIntrospection)",
			Token:              "malformed-token",
			ExpectedStatusCode: http.StatusUnauthorized,
			Endpoint:           "/context-protected",
		},
	}

	// Execute test cases for both middlewares
	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			req, err := http.NewRequest("GET", middlewareServer.URL+tc.Endpoint, nil)
			if err != nil {
				t.Fatalf("NewRequest() = %v; expected no error", err)
			}

			req.Header.Set("Authorization", "Bearer "+tc.Token)

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Failed to send request: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tc.ExpectedStatusCode {
				t.Errorf("Got status code %d, expected %d", resp.StatusCode, tc.ExpectedStatusCode)
			}
		})
	}
}

func generateTestTokens(t *testing.T) (string, string, string) {
	claims := claimsMap{
		"iss": "idp.authress.com",
		"aud": "app.authress.com",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
		"sub": "1234",
	}
	validToken, err := createSignedJWT(claims, RSAPrvKey, rs256, "0")
	if err != nil {
		t.Fatalf("createSignedJWT() = %v; but expected no error", err)
	}

	expiredToken, err := createSignedJWT(claimsMap{
		"iss": "idp.authress.com",
		"aud": "app.authress.com",
		"exp": time.Now().Add(-1 * time.Hour).Unix(),
		"sub": "1234",
	}, RSAPrvKey, rs256, "0")

	if err != nil {
		t.Fatalf("createSignedJWT() = %v; but expected no error", err)
	}

	tamperedToken, err := createTamperedJWT(claims, RSAPrvKey, rs256, "0", "aud", "fake-app")
	if err != nil {
		t.Fatalf("createTamperedJWT() = %v; but expected no error", err)
	}

	return validToken, expiredToken, tamperedToken
}

func newValidator(t *testing.T, opts ...Option) *Validator {
	var o []Option
	o = append(o, WithJWKS(newTestStore(RSAPubKey)), WithMetadata(&OAuth2ServerMetadata{Issuer: "idp.authress.com"}))
	o = append(o, opts...)
	v, err := New(o...)
	if err != nil {
		t.Fatalf("New() = %v; but expected no error", err)
	}
	return v
}
