package main

import (
	"log"
	"net/http"
	"os"

	"github.com/theadell/authress"
	"golang.org/x/oauth2"
)

var oauth2Client *oauth2.Config
var validator *authress.Validator
var sessionStore = NewSessionStore()

func init() {
	err := initTemplateCache()
	if err != nil {
		log.Fatal(err)
	}

	validator, err = authress.New(authress.WithDiscovery(os.Getenv("AUTH0_OIDC_CONFIG")))
	if err != nil {
		log.Fatal(err)
	}

	oauth2Client = &oauth2.Config{
		ClientID:     os.Getenv("AUTH0_CLIENT_ID"),
		ClientSecret: os.Getenv("AUTH0_CLIENT_SECRET"),
		RedirectURL:  "http://localhost:8080/callback",
		Scopes:       []string{"openid", "profile", "email"},
		Endpoint:     validator.ClientEndpoint(),
	}

}
func main() {

	if err := Run(); err != nil {
		log.Fatalf("Failed to start the server: %v", err)
	}
}

func Run() error {
	mux := SetupRoutes(validator)
	log.Println("Listening on localhost:8080")
	return http.ListenAndServe("localhost:8080", mux)
}
