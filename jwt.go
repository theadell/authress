package authress

import "github.com/theadell/authress/internal"

type Token struct {
	Raw     string
	header  *internal.JWTHeader
	payload *internal.JWTPayload
}

func (t *Token) Sub() string {
	return t.payload.GetStringClaim("sub")
}

func (t *Token) Iss() string {
	return t.payload.GetStringClaim("iss")
}

func (t *Token) Aud() string {
	return t.payload.GetStringClaim("aud")
}

func (t *Token) Alg() string {
	return t.header.Alg
}

func (t *Token) GetClaim(key string) any {
	return t.payload.GetClaim(key)
}

func (t *Token) GetIntClaim(key string) int {
	return t.payload.GetIntClaim(key)
}
