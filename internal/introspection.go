package internal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
)

type IntrospectionRequest struct {
	Token         string
	TokenTypeHint string
	ClientID      string
	ClientSecret  string
}

type IntrospectionResponse struct {
	Active    bool   `json:"active"`
	Scope     string `json:"scope,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	Username  string `json:"username,omitempty"`
	TokenType string `json:"token_type,omitempty"`
	Exp       int64  `json:"exp,omitempty"`
	Iat       int64  `json:"iat,omitempty"`
	Nbf       int64  `json:"nbf,omitempty"`
	Sub       string `json:"sub,omitempty"`
	Aud       string `json:"aud,omitempty"`
	Iss       string `json:"iss,omitempty"`
	Jti       string `json:"jti,omitempty"`
}

func IntrospectToken(client *http.Client, introspectionURL string, req IntrospectionRequest) (*IntrospectionResponse, error) {
	// Prepare form data for the introspection request
	form := url.Values{}
	form.Set("token", req.Token)
	if req.TokenTypeHint != "" {
		form.Set("token_type_hint", req.TokenTypeHint)
	}

	// Create the HTTP request
	httpReq, err := http.NewRequest(http.MethodPost, introspectionURL, bytes.NewBufferString(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create introspection request: %w", err)
	}

	// Set content-type and basic auth headers
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpReq.SetBasicAuth(req.ClientID, req.ClientSecret)

	// Send the request
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send introspection request: %w", err)
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read introspection response body: %w", err)
	}

	// Handle non-200 status codes
	if resp.StatusCode != http.StatusOK {
		// Create a RetrieveError instance to capture details about the error
		retrieveError := &RetrieveError{
			Response: resp,
			Body:     body,
		}

		// Attempt to parse error details from the response
		content, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
		switch content {
		case "application/x-www-form-urlencoded", "text/plain":
			// Some endpoints return a query string with error details
			vals, err := url.ParseQuery(string(body))
			if err == nil {
				retrieveError.ErrorCode = vals.Get("error")
				retrieveError.ErrorDescription = vals.Get("error_description")
				retrieveError.ErrorURI = vals.Get("error_uri")
			}
		default:
			// Try to parse error details as JSON
			var introspectionErr struct {
				Error            string `json:"error"`
				ErrorDescription string `json:"error_description"`
				ErrorURI         string `json:"error_uri"`
			}
			if err = json.Unmarshal(body, &introspectionErr); err == nil {
				retrieveError.ErrorCode = introspectionErr.Error
				retrieveError.ErrorDescription = introspectionErr.ErrorDescription
				retrieveError.ErrorURI = introspectionErr.ErrorURI
			}
		}

		return nil, retrieveError
	}

	// Decode successful response into IntrospectionResponse struct
	var introspectionResponse IntrospectionResponse
	err = json.NewDecoder(bytes.NewReader(body)).Decode(&introspectionResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to decode introspection response: %w", err)
	}

	// Return the successful introspection response
	return &introspectionResponse, nil
}

type RetrieveError struct {
	Response         *http.Response
	Body             []byte
	ErrorCode        string
	ErrorDescription string
	ErrorURI         string
}

// Error implements the error interface for RetrieveError.
func (r *RetrieveError) Error() string {
	if r.ErrorCode != "" {
		s := fmt.Sprintf("authress: %q", r.ErrorCode)
		if r.ErrorDescription != "" {
			s += fmt.Sprintf(" %q", r.ErrorDescription)
		}
		if r.ErrorURI != "" {
			s += fmt.Sprintf(" %q", r.ErrorURI)
		}
		return s
	}
	return fmt.Sprintf("authress: cannot introspect token: %v\nResponse: %s", r.Response.Status, r.Body)
}
