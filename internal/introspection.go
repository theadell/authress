package internal

import (
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
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

	httpReq, err := http.NewRequest(http.MethodPost, introspectionURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, &RetrievalError{
			Err:              "failed to create introspection request",
			ErrorDescription: err.Error(),
		}
	}

	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpReq.SetBasicAuth(req.ClientID, req.ClientSecret)

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, &RetrievalError{
			Err:              "failed to send introspection request",
			ErrorDescription: err.Error(),
		}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, &RetrievalError{
			Err:              "failed to read introspection response body",
			ErrorDescription: err.Error(),
		}
	}

	if resp.StatusCode != http.StatusOK {
		retrievalError := &RetrievalError{
			StatusCode: resp.StatusCode,
		}

		contentType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
		switch contentType {
		case "application/x-www-form-urlencoded", "text/plain":
			vals, err := url.ParseQuery(string(body))
			if err == nil {
				retrievalError.Err = vals.Get("error")
				retrievalError.ErrorDescription = vals.Get("error_description")
			}
		default:
			var errResp struct {
				Error            string `json:"error"`
				ErrorDescription string `json:"error_description"`
			}
			if err = json.Unmarshal(body, &errResp); err == nil {
				retrievalError.Err = errResp.Error
				retrievalError.ErrorDescription = errResp.ErrorDescription
			}
		}

		if retrievalError.Err == "" {
			retrievalError.Err = "introspection request failed"
		}

		return nil, retrievalError
	}

	// Decode successful response into IntrospectionResponse struct
	var introspectionResponse IntrospectionResponse
	err = json.Unmarshal(body, &introspectionResponse)
	if err != nil {
		return nil, &RetrievalError{
			Err:              "failed to decode introspection response",
			ErrorDescription: err.Error(),
		}
	}

	// Return the successful introspection response
	return &introspectionResponse, nil
}

type RetrievalError struct {
	Err              string
	ErrorDescription string
	StatusCode       int
}

func (e *RetrievalError) Error() string {
	var sb strings.Builder
	if e.Err != "" {
		sb.WriteString(e.Err)
	} else {
		sb.WriteString("retrieval error")
	}
	if e.StatusCode != 0 {
		sb.WriteString(fmt.Sprintf(" (HTTP status %d)", e.StatusCode))
	}
	if e.ErrorDescription != "" {
		sb.WriteString(fmt.Sprintf(": %s", e.ErrorDescription))
	}
	return sb.String()
}
