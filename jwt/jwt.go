package jwt

import "github.com/openware/rango/pkg/auth"

type JWTService struct {
	keys *auth.KeyStore
}

func NewJWTService(privKeyPath, pubKeyPath string) (*JWTService, error) {
	keys, err := auth.LoadOrGenerateKeys(privKeyPath, pubKeyPath)
	if err != nil {
		return nil, err
	}
	return &JWTService{keys: keys}, nil
}

func (j *JWTService) ParseJWT(jwt string) (auth.Auth, error) {
	return auth.ParseAndValidate(jwt, j.keys.PublicKey)
}
