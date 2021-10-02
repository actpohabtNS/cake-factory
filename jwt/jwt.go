package jwt

import "github.com/openware/rango/pkg/auth"

const (
	privKeyPath = "../keys/privkey.rsa"
	pubKeyPath  = "../keys/pubkey.rsa"
)

type JWTService struct {
	keys *auth.KeyStore
}

func NewJWTService() (*JWTService, error) {
	keys, err := auth.LoadOrGenerateKeys(privKeyPath, pubKeyPath)
	if err != nil {
		return nil, err
	}
	return &JWTService{keys: keys}, nil
}

func (j *JWTService) GenerateJWT(email string) (string, error) {
	return auth.ForgeToken("empty", email, "empty", 0, j.keys.PrivateKey, nil)
}

func (j *JWTService) ParseJWT(jwt string) (auth.Auth, error) {
	return auth.ParseAndValidate(jwt, j.keys.PublicKey)
}
