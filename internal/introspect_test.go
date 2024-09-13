package internal

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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

			if retrieveErr, ok := err.(*RetrievalError); ok {
				if retrieveErr.ErrorDescription != tt.expectedDescription {
					t.Errorf("ErrorDescription = %q; want %q", retrieveErr.ErrorDescription, tt.expectedDescription)
				}
			} else {
				t.Errorf("expected RetrieveError, got %T", err)
			}
		})
	}
}

func TestIntrospectToken_Errors(t *testing.T) {
	t.Run("Fail to create NewRequest", func(t *testing.T) {
		client := &http.Client{}
		introspectionURL := "http://%41:8080/" // Invalid URL to cause NewRequest to fail
		req := IntrospectionRequest{
			Token: "test_token",
		}

		_, err := IntrospectToken(client, introspectionURL, req)
		if err == nil {
			t.Fatalf("Expected error when creating request with invalid URL, got nil")
		}
		var retrievalErr *RetrievalError
		if !errors.As(err, &retrievalErr) {
			t.Errorf("Expected RetrievalError, got %T", err)
		}
		expectedError := "failed to create introspection request: parse \"http://%41:8080/\": invalid URL escape \"%41\""
		if retrievalErr.Error() != expectedError {
			t.Errorf("Expected error '%s', got '%s'", expectedError, retrievalErr.Error())
		}
	})

	t.Run("Client.Do fails", func(t *testing.T) {
		client := &http.Client{
			Transport: &FailingRoundTripper{},
		}
		introspectionURL := "http://example.com/introspect"
		req := IntrospectionRequest{
			Token: "test_token",
		}

		_, err := IntrospectToken(client, introspectionURL, req)
		if err == nil {
			t.Fatalf("Expected error when client.Do fails, got nil")
		}
		var retrievalErr *RetrievalError
		if !errors.As(err, &retrievalErr) {
			t.Errorf("Expected RetrievalError, got %T", err)
		}
		expectedError := `failed to send introspection request: Post "http://example.com/introspect": simulated client.Do failure`
		if retrievalErr.Error() != expectedError {
			t.Errorf("Expected error '%s', got '%s'", expectedError, retrievalErr.Error())
		}
	})

	t.Run("Body read fails", func(t *testing.T) {
		client := &http.Client{
			Transport: &BodyFailingRoundTripper{},
		}
		introspectionURL := "http://example.com/introspect"
		req := IntrospectionRequest{
			Token: "test_token",
		}

		_, err := IntrospectToken(client, introspectionURL, req)
		if err == nil {
			t.Fatalf("Expected error when reading response body fails, got nil")
		}
		var retrievalErr *RetrievalError
		if !errors.As(err, &retrievalErr) {
			t.Errorf("Expected RetrievalError, got %T", err)
		}
		expectedError := "failed to read introspection response body: simulated body read failure"
		if retrievalErr.Error() != expectedError {
			t.Errorf("Expected error '%s', got '%s'", expectedError, retrievalErr.Error())
		}
	})

	t.Run("Non-200 Status Code with Error Details", func(t *testing.T) {
		client := &http.Client{
			Transport: &ErrorResponseRoundTripper{
				StatusCode:  http.StatusBadRequest,
				Body:        `{"error":"invalid_request","error_description":"The request is missing a required parameter."}`,
				ContentType: "application/json",
			},
		}
		introspectionURL := "http://example.com/introspect"
		req := IntrospectionRequest{
			Token: "test_token",
		}

		_, err := IntrospectToken(client, introspectionURL, req)
		if err == nil {
			t.Fatalf("Expected error for non-200 status code, got nil")
		}
		var retrievalErr *RetrievalError
		if !errors.As(err, &retrievalErr) {
			t.Errorf("Expected RetrievalError, got %T", err)
		}
		expectedError := "invalid_request (HTTP status 400): The request is missing a required parameter."
		if retrievalErr.Error() != expectedError {
			t.Errorf("Expected error '%s', got '%s'", expectedError, retrievalErr.Error())
		}
	})

	t.Run("Non-200 Status Code without Error Details", func(t *testing.T) {
		client := &http.Client{
			Transport: &ErrorResponseRoundTripper{
				StatusCode:  http.StatusInternalServerError,
				Body:        "Internal Server Error",
				ContentType: "text/plain",
			},
		}
		introspectionURL := "http://example.com/introspect"
		req := IntrospectionRequest{
			Token: "test_token",
		}

		_, err := IntrospectToken(client, introspectionURL, req)
		if err == nil {
			t.Fatalf("Expected error for non-200 status code, got nil")
		}
		var retrievalErr *RetrievalError
		if !errors.As(err, &retrievalErr) {
			t.Errorf("Expected RetrievalError, got %T", err)
		}
		expectedError := "introspection request failed (HTTP status 500)"
		if retrievalErr.Error() != expectedError {
			t.Errorf("Expected error '%s', got '%s'", expectedError, retrievalErr.Error())
		}
	})
}

type FailingRoundTripper struct{}

func (f *FailingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("simulated client.Do failure")
}

type BodyFailingRoundTripper struct{}

func (b *BodyFailingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       &FailingReadCloser{},
		Header:     make(http.Header),
	}, nil
}

type FailingReadCloser struct{}

func (f *FailingReadCloser) Read(p []byte) (n int, err error) {
	return 0, fmt.Errorf("simulated body read failure")
}

func (f *FailingReadCloser) Close() error {
	return nil
}

type ErrorResponseRoundTripper struct {
	StatusCode  int
	Body        string
	ContentType string
}

func (e *ErrorResponseRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: e.StatusCode,
		Status:     http.StatusText(e.StatusCode),
		Body:       io.NopCloser(strings.NewReader(e.Body)),
		Header: http.Header{
			"Content-Type": []string{e.ContentType},
		},
	}, nil
}
