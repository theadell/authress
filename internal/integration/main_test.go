//go:build integration
// +build integration

package integration

import (
	"context"
	"fmt"
	"log"
	"os"
	"testing"
	"time"

	"github.com/Nerzal/gocloak/v13"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

var (
	kcContainer    testcontainers.Container
	kcBaseUrl      string
	kcDiscoveryUrl string
	kcClient       *gocloak.GoCloak
	clientID       = "authress-test-client"
	clientSecret   = "test-secret"

	user = gocloak.User{
		FirstName:     gocloak.StringP("bob"),
		Email:         gocloak.StringP("bob@authress.com"),
		Enabled:       gocloak.BoolP(true),
		Username:      gocloak.StringP("thebob"),
		EmailVerified: gocloak.BoolP(true),
	}
)

func TestMain(m *testing.M) {
	ctx := context.Background()
	username, password := "admin", "admin"

	// Start Keycloak container
	kcContainer, kcBaseUrl = startKeycloakContainer(ctx, username, password)
	kcDiscoveryUrl = fmt.Sprintf("%s/%s", kcBaseUrl, "realms/master/.well-known/openid-configuration")
	// Initialize GoCloak client
	kcClient = gocloak.NewClient(kcBaseUrl)

	// Setup Keycloak environment (realm, client, user)
	err := setupTestEnv(kcClient, username, password)
	if err != nil {
		log.Fatalf("failed to setup Keycloak environment: %s", err)
	}

	// Run tests
	code := m.Run()

	// Terminate Keycloak container
	err = kcContainer.Terminate(ctx)
	if err != nil {
		log.Fatalf("Failed to terminate Keycloak container: %s", err)
	}

	os.Exit(code)
}

func startKeycloakContainer(ctx context.Context, username, password string) (testcontainers.Container, string) {
	req := testcontainers.ContainerRequest{
		Image:        "quay.io/keycloak/keycloak:25.0.2",
		ExposedPorts: []string{"8080/tcp"},
		Env: map[string]string{
			"KEYCLOAK_ADMIN":          username,
			"KEYCLOAK_ADMIN_PASSWORD": password,
		},
		Cmd:        []string{"start-dev"},
		WaitingFor: wait.ForHTTP("/realms/master").WithPort("8080").WithStartupTimeout(60 * time.Second),
	}

	kcContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		log.Fatalf("Could not start Keycloak container: %s", err)
	}

	host, err := kcContainer.Host(ctx)
	if err != nil {
		log.Fatalf("Failed to get container host: %s", err)
	}

	port, err := kcContainer.MappedPort(ctx, "8080")
	if err != nil {
		log.Fatalf("Failed to get container port: %s", err)
	}

	kcBaseUrl := fmt.Sprintf("http://%s:%s", host, port.Port())
	return kcContainer, kcBaseUrl
}

func setupTestEnv(client *gocloak.GoCloak, username, password string) error {
	ctx := context.Background()

	// Admin login to get the access token for master realm
	token, err := client.LoginAdmin(ctx, username, password, "master")
	if err != nil {
		return fmt.Errorf("admin login failed: %w", err)
	}
	adminToken := token.AccessToken

	// Create client in the master realm with direct access grants enabled
	clientRep := gocloak.Client{
		ClientID:                  gocloak.StringP(clientID),
		Enabled:                   gocloak.BoolP(true),
		RedirectURIs:              &[]string{"*"},
		PublicClient:              gocloak.BoolP(false),
		DirectAccessGrantsEnabled: gocloak.BoolP(true),
		Secret:                    gocloak.StringP(clientSecret),
	}

	// Create the client in the master realm
	_, err = client.CreateClient(ctx, adminToken, "master", clientRep)
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	return nil
}
