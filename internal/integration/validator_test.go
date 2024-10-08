//go:build integration
// +build integration

package integration

import (
	"context"
	"testing"

	"github.com/theadell/authress"
)

func TestAuthServerDiscovery(t *testing.T) {
	_, err := authress.New(authress.WithDiscovery(kcDiscoveryUrl))
	if err != nil {
		t.Errorf("failed to create validator: %v", err)
	}
}

func TestTokenIntrospection(t *testing.T) {
	v, err := authress.New(
		authress.WithDiscovery(kcDiscoveryUrl),
		authress.WithIntrospection(clientID, clientSecret))
	if err != nil {
		t.Errorf("failed to create validator: %v", err)
	}

	tokenResp, err := kcClient.LoginAdmin(context.TODO(), "admin", "admin", "master")
	if err != nil {
		t.Fatalf("failed to login as admin: %v", err)
	}
	token := tokenResp.AccessToken

	active, err := v.IntrospectToken(context.TODO(), token)
	if err != nil {
		t.Fatalf("failed to introspect token: %v", err)
	}

	if !active {
		t.Errorf("expected token to be active, but it is inactive")
	}
}

func TestValidateToken(t *testing.T) {
	v, err := authress.New(authress.WithDiscovery(kcDiscoveryUrl))
	if err != nil {
		t.Errorf("failed to create validator: %v", err)
	}

	tokenResp, err := kcClient.LoginAdmin(context.TODO(), "admin", "admin", "master")
	if err != nil {
		t.Fatalf("failed to login as admin: %v", err)
	}
	token := tokenResp.AccessToken

	tt, err := v.ValidateJWT(token)
	if err != nil {
		t.Errorf("did not expect an error but ValidateJWT(token) retruned: %v", err)
	}
	if tt.Claims.GetStringClaim("preferred_username") != "admin" {
		t.Errorf("incorrect email claim. Expected %q, but %q", "admin", tt.Claims.GetStringClaim("preferred_username"))
	}

}
