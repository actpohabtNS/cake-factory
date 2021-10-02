package main

import (
	"crypto/md5"
	"encoding/json"
	"errors"
	"github.com/actpohabtNS/cake-factory/jwt"
	"net/http"
	"strings"
)

type MyJWTService struct {
	*jwt.JWTService
}

func MyNewJWTService() (*MyJWTService, error) {
	jwtService, err := jwt.NewJWTService()
	return &MyJWTService{jwtService}, err
}

type JWTParams struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (u *UserService) JWT(w http.ResponseWriter, r *http.Request, jwtService *MyJWTService) {
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

	token, jwtErr := jwtService.GenerateJWT(user.Email)

	if jwtErr != nil {
		handleUnprocError(jwtErr, w)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(token))
}

type ProtectedHandler func(rw http.ResponseWriter, r *http.Request, u User, userService UserService)

func (j *MyJWTService) jwtAuthRoleExecutor(minimalAccessRole Role, us UserService, h ProtectedHandler) http.HandlerFunc {
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

func (j *MyJWTService) jwtAuth(us UserService, h ProtectedHandler) http.HandlerFunc {
	return j.jwtAuthRoleExecutor(UserRole, us, h)
}

func (j *MyJWTService) jwtAuthAdmin(us UserService, h ProtectedHandler) http.HandlerFunc {
	return j.jwtAuthRoleExecutor(AdminRole, us, h)
}

func (j *MyJWTService) jwtAuthSuperAdmin(us UserService, h ProtectedHandler) http.HandlerFunc {
	return j.jwtAuthRoleExecutor(SuperAdminRole, us, h)
}
