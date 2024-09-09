package internal

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIntrospectTokenRequest(t *testing.T) {
	const clientID = "testClient"
	const clientSecret = "testSecret"
	const token = "ya29.a0AfH6SMA9tWvGxj2Q-nLh-DLXHAXXKk5aNkksdsdfgXPdkz7XXm"
	const tokenType = "bearer"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != clientID || p != clientSecret {
			t.Errorf("basic auth not set correct, got %q:%q; want %q:%q", u, p, clientID, clientSecret)
		}
		if got, want := r.FormValue("token"), token; got != want {
			t.Errorf("token = %q; want %q", got, want)
		}
		if got, want := r.FormValue("token_type_hint"), tokenType; got != want {
			t.Errorf("token_hint = %q; want empty", got)
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"active": true, "token_type": "bearer"}`)
	}))
	defer ts.Close()
	client := ts.Client()
	res, err := IntrospectToken(client, ts.URL, IntrospectionRequest{Token: token, ClientID: clientID, ClientSecret: clientSecret, TokenTypeHint: "bearer"})
	if err != nil {
		t.Errorf("IntrospectToken = %v; want no error", err)
	}
	if res.Active != true {
		t.Errorf("active = %t; want %t", res.Active, true)
	}
	if res.TokenType != "bearer" {
		t.Errorf("token_type = %q; want %q", res.TokenType, "bearer")
	}
}

func TestIntrospectTokenError(t *testing.T) {
	const clientID = "testClient"
	const clientSecret = "testSecret"
	const token = "ya29.a0AfH6SMA9tWvGxj2Q-nLh-DLXHAXXKk5aNkksdsdfgXPdkz7XXm"
	const tokenType = "bearer"

	tests := []struct {
		name                string
		queryParam          string
		responseFormat      string
		expectedResponse    string
		expectedDescription string
	}{
		{
			name:                "JSON error response",
			queryParam:          "json",
			responseFormat:      "application/json",
			expectedResponse:    `{"error": "invalid_request", "error_description": "The token is invalid."}`,
			expectedDescription: "The token is invalid.",
		},
		{
			name:                "Form-encoded error response",
			queryParam:          "form",
			responseFormat:      "application/x-www-form-urlencoded",
			expectedResponse:    `error=invalid_request&error_description=The+token+is+invalid.`,
			expectedDescription: "The token is invalid.",
		},
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != clientID || p != clientSecret {
			t.Errorf("basic auth not set correctly, got %q:%q; want %q:%q", u, p, clientID, clientSecret)
		}
		if got, want := r.FormValue("token"), token; got != want {
			t.Errorf("token = %q; want %q", got, want)
		}
		if got, want := r.FormValue("token_type_hint"), tokenType; got != want {
			t.Errorf("token_type_hint = %q; want %q", got, want)
		}

		query := r.URL.Query().Get("format")
		switch query {
		case "json":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			io.WriteString(w, `{"error": "invalid_request", "error_description": "The token is invalid."}`)
		case "form":
			w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
			w.WriteHeader(http.StatusBadRequest)
			io.WriteString(w, `error=invalid_request&error_description=The+token+is+invalid.`)
		default:
			t.Errorf("unsupported response format: %s", query)
		}
	}))
	defer ts.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := ts.Client()

			res, err := IntrospectToken(client, ts.URL+"?format="+tt.queryParam, IntrospectionRequest{
				Token:         token,
				ClientID:      clientID,
				ClientSecret:  clientSecret,
				TokenTypeHint: tokenType,
			})

			if res != nil {
				t.Errorf("expected nil response, got %+v", res)
			}

			if err == nil {
				t.Errorf("expected an error, got nil")
			}

			if retrieveErr, ok := err.(*RetrieveError); ok {
				if retrieveErr.ErrorDescription != tt.expectedDescription {
					t.Errorf("ErrorDescription = %q; want %q", retrieveErr.ErrorDescription, tt.expectedDescription)
				}
			} else {
				t.Errorf("expected RetrieveError, got %T", err)
			}
		})
	}
}
