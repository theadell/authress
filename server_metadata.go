package authress

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/MicahParks/jwkset"
	"golang.org/x/oauth2"
)

type OAuth2ServerMetadata struct {
	Issuer                            string   `json:"issuer"`
	AuthEndpoint                      string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	DeviceAuthEndpoint                string   `json:"device_authorization_endpoint"`
	JWKURI                            string   `json:"jwks_uri"`
	IntrospectionEndpoint             string   `json:"introspection_endpoint"`
	IntrospectionAuthMethodsSupported []string `json:"introspection_endpoint_auth_methods_supported"`
	RevocationEndpoint                string   `json:"revocation_endpoint"`
	RevocationAuthMethodsSupported    []string `json:"revocation_endpoint_auth_methods_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgsSupported       []string `json:"id_token_signing_alg_values_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
}

func (m *OAuth2ServerMetadata) Endpoint() oauth2.Endpoint {
	return oauth2.Endpoint{
		AuthURL:       m.AuthEndpoint,
		DeviceAuthURL: m.DeviceAuthEndpoint,
		TokenURL:      m.TokenEndpoint,
	}
}

func discoverOAuth2ServerMetadata(client *http.Client, discoveryUrl string) (*OAuth2ServerMetadata, jwkset.Storage, error) {
	resp, err := client.Get(discoveryUrl)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("failed to fetch server metadata with status code: %d", resp.StatusCode)
	}

	var metadata OAuth2ServerMetadata
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return nil, nil, fmt.Errorf("failed to decode server metadata %w", err)
	}

	jwks, err := jwkset.NewDefaultHTTPClient([]string{metadata.JWKURI})
	if err != nil {
		return nil, nil, err
	}
	return &metadata, jwks, nil
}
