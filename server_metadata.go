package authress

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/theadell/authress/internal"
	"golang.org/x/oauth2"
)

type OAuth2ServerMetadata struct {
	Issuer                 string   `json:"issuer"`
	AuthEndpoint           string   `json:"authorization_endpoint"`
	TokenEndpoint          string   `json:"token_endpoint"`
	DeviceAuthEndpoint     string   `json:"device_authorization_endpoint"`
	JWKURI                 string   `json:"jwks_uri"`
	IntrospecetEndpoint    string   `json:"introspection_endpoint"`
	IntrospecetAuthMethods []string `json:"introspection_endpoint_auth_methods_supported"`
}

func (m *OAuth2ServerMetadata) Endpoint() oauth2.Endpoint {
	return oauth2.Endpoint{
		AuthURL:       m.AuthEndpoint,
		DeviceAuthURL: m.DeviceAuthEndpoint,
		TokenURL:      m.TokenEndpoint,
	}
}

func discoverOAuth2ServerMetadata(client *http.Client, discoveryUrl string) (*OAuth2ServerMetadata, map[string]*rsa.PublicKey, error) {
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

	jwks, err := internal.FetchJWKS(client, metadata.JWKURI)
	if err != nil {
		return nil, nil, err
	}
	keysMap := make(map[string]*rsa.PublicKey)

	for _, key := range jwks.Keys {
		rsaKey, err := internal.JWKToRSAPublicKey(key)
		if err != nil {
			continue
		}
		keysMap[key.Kid] = rsaKey
	}
	return &metadata, keysMap, nil
}
