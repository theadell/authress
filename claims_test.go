package authress

import (
	"testing"
	"time"
)

func TestGetClaimAs(t *testing.T) {

	claims := &Claims{rawPayload: []byte(`
	{
	  "address": {
		"street": "123 Main St",
		"city": "Metropolis",
		"zip": "54321"
	  },
	  "company": {
		"name": "Tech Innovations",
		"department": {
		  "name": "Engineering",
		  "lead": {
			"name": "Alice Wonder",
			"email": "alice.wonder@techinnovations.com"
		  }
		}
	  }
	}`)}

	type Address struct {
		Street string `json:"street"`
		City   string `json:"city"`
		Zip    string `json:"zip"`
	}

	type Lead struct {
		Name  string `json:"name"`
		Email string `json:"email"`
	}

	type Department struct {
		Name string `json:"name"`
		Lead Lead   `json:"lead"`
	}

	type Company struct {
		Name       string     `json:"name"`
		Department Department `json:"department"`
	}

	var address Address
	if err := claims.GetClaimAs("address", &address); err != nil {
		t.Fatalf("failed to get address claim: %v", err)
	}

	if address.Street != "123 Main St" {
		t.Errorf("expected street '123 Main St' but got %s", address.Street)
	}
	if address.City != "Metropolis" {
		t.Errorf("expected city 'Metropolis' but got %s", address.City)
	}
	if address.Zip != "54321" {
		t.Errorf("expected zip '54321' but got %s", address.Zip)
	}

	var company Company
	if err := claims.GetClaimAs("company", &company); err != nil {
		t.Fatalf("failed to get company claim: %v", err)
	}

	if company.Name != "Tech Innovations" {
		t.Errorf("expected company name 'Tech Innovations' but got %s", company.Name)
	}
	if company.Department.Name != "Engineering" {
		t.Errorf("expected department name 'Engineering' but got %s", company.Department.Name)
	}
	if company.Department.Lead.Name != "Alice Wonder" {
		t.Errorf("expected lead name 'Alice Wonder' but got %s", company.Department.Lead.Name)
	}
	if company.Department.Lead.Email != "alice.wonder@techinnovations.com" {
		t.Errorf("expected lead email 'alice.wonder@techinnovations.com' but got %s", company.Department.Lead.Email)
	}
}

func TestGetClaimAsErr(t *testing.T) {

	type Address struct {
		Street string `json:"street"`
		City   string `json:"city"`
		Zip    string `json:"zip"`
	}

	payload := `{
		"address": {
			"street": "123 Main St",
			"city": "Metropolis",
			"zip": "54321"
		}
	}`
	claims := Claims{rawPayload: []byte(payload)}

	tests := []struct {
		name      string
		key       string
		variable  interface{}
		expectErr bool
	}{
		{
			name:      "Valid key and pointer",
			key:       "address",
			variable:  &Address{},
			expectErr: false,
		},
		{
			name:      "Empty key",
			key:       "",
			variable:  &Address{},
			expectErr: true,
		},
		{
			name:      "Non-pointer variable",
			key:       "address",
			variable:  Address{},
			expectErr: true,
		},
		{
			name:      "Nil pointer",
			key:       "address",
			variable:  (*Address)(nil),
			expectErr: true,
		},
		{
			name:      "Non-existent key",
			key:       "",
			variable:  &Address{},
			expectErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := claims.GetClaimAs(tc.key, tc.variable)
			if (err != nil) != tc.expectErr {
				t.Errorf("Test %s failed: expected error %v, got %v", tc.name, tc.expectErr, err)
			}
		})
	}
}

func TestClaimsTransformations(t *testing.T) {
	timeTests := []struct {
		name         string
		claims       Claims
		expectedTime time.Time
		timeFunc     func(c *Claims) time.Time
	}{
		{
			name: "ExpiresAtTime valid",
			claims: Claims{
				ExpiresAt: 1633024800,
			},
			expectedTime: time.Unix(1633024800, 0),
			timeFunc:     (*Claims).ExpiresAtTime,
		},
		{
			name: "IssuedAtTime valid",
			claims: Claims{
				IssuedAt: 1609459200,
			},
			expectedTime: time.Unix(1609459200, 0),
			timeFunc:     (*Claims).IssuedAtTime,
		},
		{
			name: "NotBeforeTime valid",
			claims: Claims{
				NotBefore: 1609459200,
			},
			expectedTime: time.Unix(1609459200, 0),
			timeFunc:     (*Claims).NotBeforeTime,
		},
	}

	for _, tt := range timeTests {
		t.Run(tt.name, func(t *testing.T) {
			actualTime := tt.timeFunc(&tt.claims)
			if !actualTime.Equal(tt.expectedTime) {
				t.Errorf("expected %v, got %v", tt.expectedTime, actualTime)
			}
		})
	}

	scopeTests := []struct {
		name           string
		claims         Claims
		expectedScopes []string
	}{
		{
			name: "Scopes with multiple scopes",
			claims: Claims{
				Scope: "read write delete",
			},
			expectedScopes: []string{"read", "write", "delete"},
		},
		{
			name: "Scopes with single scope",
			claims: Claims{
				Scope: "read",
			},
			expectedScopes: []string{"read"},
		},
		{
			name: "Scopes with empty string",
			claims: Claims{
				Scope: "",
			},
			expectedScopes: []string{},
		},
	}

	for _, st := range scopeTests {
		t.Run(st.name, func(t *testing.T) {
			actualScopes := st.claims.Scopes()
			if len(actualScopes) != len(st.expectedScopes) {
				t.Errorf("expected %d scopes, got %d", len(st.expectedScopes), len(actualScopes))
			}
			for i, scope := range st.expectedScopes {
				if actualScopes[i] != scope {
					t.Errorf("expected scope %s, got %s", scope, actualScopes[i])
				}
			}
		})
	}
}

func TestAudience_UnmarshalJSON(t *testing.T) {
	// Define test cases
	tests := []struct {
		name        string
		input       []byte
		expected    audience
		expectError bool
	}{
		{
			name:        "Single string audience",
			input:       []byte(`"example.com"`),
			expected:    audience{"example.com"},
			expectError: false,
		},
		{
			name:        "Array of strings audience",
			input:       []byte(`["example.com", "api.example.com"]`),
			expected:    audience{"example.com", "api.example.com"},
			expectError: false,
		},
		{
			name:        "Invalid format",
			input:       []byte(`123`),
			expected:    nil,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var audience audience
			err := audience.UnmarshalJSON(tt.input)
			if (err != nil) != tt.expectError {
				t.Errorf("UnmarshalJSON() error = %v, wantError %v", err, tt.expectError)
			}
			if err == nil && len(audience) != len(tt.expected) {
				t.Errorf("UnmarshalJSON() = %v, want %v", audience, tt.expected)
			}
			for i := range audience {
				if audience[i] != tt.expected[i] {
					t.Errorf("UnmarshalJSON() = %v, want %v", audience, tt.expected)
				}
			}
		})
	}
}

func TestClaims_HasAudience(t *testing.T) {
	// Define test cases
	tests := []struct {
		name        string
		claims      Claims
		audiences   []string
		expectFound bool
	}{
		{
			name:        "Audience found",
			claims:      Claims{Audience: audience{"example.com", "api.example.com"}},
			audiences:   []string{"api.example.com"},
			expectFound: true,
		},
		{
			name:        "Audience not found",
			claims:      Claims{Audience: audience{"example.com", "api.example.com"}},
			audiences:   []string{"other.com"},
			expectFound: false,
		},
		{
			name:        "Empty audience list",
			claims:      Claims{Audience: audience{}},
			audiences:   []string{"example.com"},
			expectFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			found := tt.claims.hasAudience(tt.audiences...)
			if found != tt.expectFound {
				t.Errorf("hasAudience() = %v, want %v", found, tt.expectFound)
			}
		})
	}
}
