package authress

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

func TestOAuthServerMetadata(t *testing.T) {
	tests := []struct {
		name             string
		metadataResp     string
		metadataCode     int
		jwksResp         string
		jwksCode         int
		expectError      bool
		expectIssuer     string
		expectJWKSValid  bool
		invalidJWKsurl   bool
		invalidServerUrl bool
	}{
		{
			name: "successful metadata and JWKS discovery",
			metadataResp: `{
				"issuer": "https://accounts.google.com",
				"authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
				"token_endpoint": "https://oauth2.googleapis.com/token",
				"jwks_uri": "{{jwks_uri}}"
			}`,
			metadataCode: http.StatusOK,
			jwksResp: `{
				"keys": [
					{
					  "e": "AQAB",
					  "alg": "RS256",
					  "use": "sig",
					  "kid": "test-key-1",
					  "n": "test-modulus-1",
					  "kty": "RSA"
					},
					{
					  "e": "AQAB",
					  "alg": "RS256",
					  "use": "sig",
					  "kid": "test-key-2",
					  "n": "test-modulus-2",
					  "kty": "RSA"
					}
				]
			}`,
			jwksCode:        http.StatusOK,
			expectError:     false,
			expectIssuer:    "https://accounts.google.com",
			expectJWKSValid: true,
		},

		{
			name:         "error with invalid metadata JSON",
			metadataResp: `invalid JSON`,
			metadataCode: http.StatusOK,
			expectError:  true,
		},
		{
			name: "error with non-200 JWKS response",
			metadataResp: `{
				"issuer": "https://accounts.google.com",
				"authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
				"token_endpoint": "https://oauth2.googleapis.com/token",
				"jwks_uri": "{{jwks_uri}}"
			}`,
			metadataCode: http.StatusOK,
			jwksResp:     ``,
			jwksCode:     http.StatusInternalServerError,
			expectError:  true,
		},
		{
			name: "error with invalid JWKS JSON",
			metadataResp: `{
				"issuer": "https://accounts.google.com",
				"authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
				"token_endpoint": "https://oauth2.googleapis.com/token",
				"jwks_uri": "{{jwks_uri}}"
			}`,
			metadataCode: http.StatusOK,
			jwksResp:     `invalid JSON`,
			jwksCode:     http.StatusOK,
			expectError:  true,
		},
		{
			name:         "non-200 metadata response code",
			metadataCode: http.StatusBadGateway,
			expectError:  true,
		},
		{
			name: "invalid jwks url",
			metadataResp: `{
				"issuer": "https://accounts.google.com",
				"authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
				"token_endpoint": "https://oauth2.googleapis.com/token",
				"jwks_uri": "{{jwks_uri}}"
			}`,
			expectError:    true,
			invalidJWKsurl: true,
			metadataCode:   http.StatusOK,
			jwksCode:       http.StatusOK,
		},
		{
			name:             "invalik discovery url",
			invalidServerUrl: true,
			expectError:      true,
			metadataCode:     http.StatusOK,
			jwksCode:         http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/jwks" {
					w.WriteHeader(tt.jwksCode)
					w.Write([]byte(tt.jwksResp))
				} else {
					var metadataResp string
					if tt.invalidJWKsurl {
						metadataResp = strings.Replace(tt.metadataResp, "{{jwks_uri}}", "://invalid-url", 1)
					} else {
						metadataResp = strings.Replace(tt.metadataResp, "{{jwks_uri}}", "http://"+r.Host+"/jwks", 1)
					}
					if tt.invalidJWKsurl {
					}
					w.WriteHeader(tt.metadataCode)
					w.Write([]byte(metadataResp))
				}
			}))
			defer server.Close()

			client := server.Client()
			var url string
			if tt.invalidServerUrl {
				url = "://invalid-url"
			} else {
				url = server.URL
			}
			metadata, jwks, err := discoverOAuth2ServerMetadata(client, url)

			if tt.expectError {
				if err == nil {
					t.Fatalf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if metadata == nil {
				t.Fatalf("expected metadata but got nil")
			}

			if metadata.Issuer != tt.expectIssuer {
				t.Errorf("expected issuer %v, got %v", tt.expectIssuer, metadata.Issuer)
			}

			if (jwks != nil) != tt.expectJWKSValid {
				t.Errorf("expected JWKS valid: %v, got: %v", tt.expectJWKSValid, jwks != nil)
			}
		})
	}
}

func TestServerMetadataOAuth2Endpoint(t *testing.T) {
	metadataResp := `{
		"issuer": "https://accounts.google.com",
		"authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
		"token_endpoint": "https://oauth2.googleapis.com/token",
		"device_authorization_endpoint": "https://oauth2.googleapis.com/device/code",
		"jwks_uri": "{{jwks_uri}}"
	}`

	jwksResp := `{
		"keys": [
			{
			  "e": "AQAB",
			  "alg": "RS256",
			  "use": "sig",
			  "kid": "test-key-1",
			  "n": "test-modulus-1",
			  "kty": "RSA"
			},
			{
			  "e": "AQAB",
			  "alg": "RS256",
			  "use": "sig",
			  "kid": "test-key-2",
			  "n": "test-modulus-2",
			  "kty": "RSA"
			}
		]
	}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/jwks" {
			w.Write([]byte(jwksResp))
		} else {
			metadataResp := strings.Replace(metadataResp, "{{jwks_uri}}", "http://"+r.Host+"/jwks", 1)
			w.Write([]byte(metadataResp))
		}
	}))
	defer server.Close()

	client := server.Client()
	metadata, _, err := discoverOAuth2ServerMetadata(client, server.URL)
	if err != nil {
		t.Fatalf("discoverOAuth2ServerMetadata(). Unexpected error %v", err)
	}
	want := oauth2.Endpoint{AuthURL: "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL: "https://oauth2.googleapis.com/token", DeviceAuthURL: "https://oauth2.googleapis.com/device/code"}
	got := metadata.Endpoint()
	if !reflect.DeepEqual(want, got) {
		t.Errorf("want %v, got %v", want, got)
	}

}
