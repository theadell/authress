//go:build integration
// +build integration

package integration

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/theadell/authress"
	"github.com/theadell/authress/middleware"
)

func TestAuthenticateMiddleWare(t *testing.T) {
	val, err := authress.NewValidator(authress.WithAuthServerDiscovery(kcDiscoveryUrl))
	if err != nil {
		t.Fatalf("failed to create validator %v", err.Error())
	}

	mw := middleware.RequireAuthJWT(val)
	svr := httptest.NewServer(mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})))

	client := svr.Client()
	resp, err := client.Get(svr.URL)
	if err != nil {
		t.Fatalf("Request to server failed with error %v", err.Error())
	}

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected %q status code but got %q", http.StatusUnauthorized, resp.Status)
	}
}
