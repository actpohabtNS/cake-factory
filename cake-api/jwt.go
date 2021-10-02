package main

import (
	"crypto/md5"
	"encoding/json"
	"errors"
	"github.com/openware/rango/pkg/auth"
	"net/http"
	"strings"
)

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

func (j *JWTService) GenerateJWT(u User) (string, error) {
	return auth.ForgeToken("empty", u.Email, "empty", 0, j.keys.PrivateKey, nil)
}

func (j *JWTService) ParseJWT(jwt string) (auth.Auth, error) {
	return auth.ParseAndValidate(jwt, j.keys.PublicKey)
}

type JWTParams struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (u *UserService) JWT(w http.ResponseWriter, r *http.Request, jwtService *JWTService) {
	params := &JWTParams{}
	decErr := json.NewDecoder(r.Body).Decode(params)

	if decErr != nil {
		handleUnprocError(errors.New("could not read params"), w)
		return
	}

	passwordDigest := md5.New().Sum([]byte(params.Password))
	user, err := u.repository.Get(params.Email)

	if err != nil {
		handleUnprocError(err, w)
		return
	}

	if string(passwordDigest) != user.PasswordDigest {
		handleUnprocError(errors.New("invalid login credentials"), w)
		return
	}

	if user.Banned {
		handleUnauthError(errors.New("you are banned! Reason: "+
			user.BanHistory[len(user.BanHistory)-1].Reason),
			w)
		return
	}

	token, jwtErr := jwtService.GenerateJWT(user)

	if jwtErr != nil {
		handleUnprocError(jwtErr, w)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(token))
}

type ProtectedHandler func(rw http.ResponseWriter, r *http.Request, u User, userService UserService)

func (j *JWTService) jwtAuthRoleExecutor(minimalAccessRole Role, us UserService, h ProtectedHandler) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		token := strings.TrimPrefix(authHeader, "Bearer ")
		jwtAuth, err := j.ParseJWT(token)
		if err != nil {
			handleUnauthError(errors.New("unauthorized"), rw)
			return
		}
		user, err := us.repository.Get(jwtAuth.Email)
		if err != nil {
			handleUnauthError(errors.New("unauthorized"), rw)
			return
		}
		if user.Banned {
			handleUnauthError(errors.New("you are banned! Reason: "+
				user.BanHistory[len(user.BanHistory)-1].Reason),
				rw)
			return
		}
		if user.Role < minimalAccessRole {
			handleUnauthError(errors.New("permission denied"), rw)
			return
		}
		h(rw, r, user, us)
	}
}

func (j *JWTService) jwtAuth(us UserService, h ProtectedHandler) http.HandlerFunc {
	return j.jwtAuthRoleExecutor(UserRole, us, h)
}

func (j *JWTService) jwtAuthAdmin(us UserService, h ProtectedHandler) http.HandlerFunc {
	return j.jwtAuthRoleExecutor(AdminRole, us, h)
}

func (j *JWTService) jwtAuthSuperAdmin(us UserService, h ProtectedHandler) http.HandlerFunc {
	return j.jwtAuthRoleExecutor(SuperAdminRole, us, h)
}
