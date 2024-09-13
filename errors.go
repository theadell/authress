package authress

import "errors"

var (
	ErrInvalidJWT           = errors.New("token format is not valid")
	ErrInvalidSignature     = errors.New("token format is not valid")
	ErrUnsupportedAlgorithm = errors.New("unsupported signing algorithm")
	ErrInvalidPublicKey     = errors.New("invalid or unsupported public key")
	errInvalidPrivateKey    = errors.New("invalid private key")
	ErrInvalidIssuer        = errors.New("invalid issuer")
	ErrTokenExpired         = errors.New("token has expired")
	ErrTokenNotYetValid     = errors.New("token is not yet valid; nbf > time.Now()")
	ErrInvalidAudience      = errors.New("invalid audience claim")
	ErrCalimNotExists       = errors.New("claim doesn't exist")
	ErrDiscoveryFailure     = errors.New("failed to discover OAuth2 server metadata")
)
