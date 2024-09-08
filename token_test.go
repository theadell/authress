package authress

import (
	"reflect"
	"testing"

	"github.com/theadell/authress/internal"
)

func TestToken(t *testing.T) {

	iss := "iss"
	aud := []string{"app-1", "app-2"}
	sub := "user-1"
	role := "user"
	exp, nbf := int64(123), int64(123)
	xId := 1.0

	tt := &internal.Token{
		Header: internal.JWTHeader{
			Kid: "123",
			Alg: "RSA",
		},
		Claims: map[string]any{
			"sub":  sub,
			"role": role,
			"x-id": xId,
		},
		Iss: iss,
		Aud: aud,
		Exp: exp,
		Nbf: nbf,
	}
	token := Token{t: tt}

	if token.Iss() != iss {
		t.Errorf("got %q, wanted %q", token.Iss(), iss)
	}
	if !reflect.DeepEqual(token.Aud(), aud) {
		t.Errorf("got %q, wanted %q", token.Aud(), aud)
	}
	if token.Sub() != sub {
		t.Errorf("got %q, wanted %q", token.Sub(), sub)
	}
	if token.GetStringClaim("role") != role {
		t.Errorf("got %q, wanted %q", token.GetStringClaim("role"), role)
	}
	if token.Nbf() != nbf {
		t.Errorf("got %q, wanted %q", token.Nbf(), nbf)
	}
	if token.Exp() != exp {
		t.Errorf("got %q, wanted %q", token.Exp(), exp)
	}
	if token.Alg() != "RSA" {
		t.Errorf("got %q, wanted %q", token.Alg(), "RSA")
	}

	if token.GetInt64Claim("x-id") != int64(xId) {
		t.Errorf("got %q, wanted %q", token.GetInt64Claim("x-id"), int64(xId))
	}
}
