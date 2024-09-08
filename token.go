package authress

import "github.com/theadell/authress/internal"

type Token struct {
	Raw string
	t   *internal.Token
}

func (t *Token) Sub() string {
	s, _ := t.t.GetStringClaim("sub")
	return s
}

func (t *Token) Iss() string {
	return t.t.Iss
}

func (t *Token) Aud() []string {
	return t.t.Aud
}

func (t *Token) Nbf() int64 {
	return t.t.Nbf
}

func (t *Token) Exp() int64 {
	return t.t.Exp
}
func (t *Token) Alg() string {
	return t.t.Header.Alg
}

func (t *Token) GetClaim(key string) any {
	c, _ := t.t.GetClaim(key)
	return c
}

func (t *Token) GetStringClaim(key string) string {
	c, _ := t.t.GetStringClaim(key)
	return c
}

func (t *Token) GetInt64Claim(key string) int64 {
	c, _ := t.t.GetInt64Claim(key)
	return int64(c)
}
