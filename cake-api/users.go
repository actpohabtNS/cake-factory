package main

import (
	"crypto/md5"
	"encoding/json"
	"errors"
	"net/http"
	"net/mail"
)

type User struct {
	Email          string
	Role           Role
	Banned         bool
	PasswordDigest string
	FavoriteCake   string
	BanHistory     BanHistory
}
type UserRepository interface {
	Add(string, User) error
	Get(string) (User, error)
	Update(string, User) error
	Delete(string) (User, error)
}

type UserService struct {
	repository UserRepository
	notifier   chan []byte
	reg        chan []bool
	cake       chan []bool
}
type UserRegisterParams struct {
	Email        string `json:"email"`
	Password     string `json:"password"`
	FavoriteCake string `json:"favorite_cake"`
}

func validateEmail(email string) error {
	if _, err := mail.ParseAddress(email); err != nil {
		return errors.New("must provide an email")
	}
	return nil
}

func validatePassword(password string) error {
	// 2. Password at least 8 symbols
	if len(password) < 8 {
		return errors.New("password must be at least 8 symbols")
	}
	return nil
}

func validateFavoriteCake(cake string) error {
	// 3. Favorite cake not empty
	if len(cake) < 1 {
		return errors.New("favourite cake can't be empty")
	}
	// 4. Favorite cake only alphabetic
	for _, charVariable := range cake {
		if (charVariable < 'a' || charVariable > 'z') && (charVariable < 'A' || charVariable > 'Z') {
			return errors.New("favourite cake must contain only alphabetic characters")
		}
	}
	return nil
}

func validateRegisterParams(p *UserRegisterParams) error {
	err := validateFavoriteCake(p.FavoriteCake)
	if err != nil {
		return err
	}

	err = validatePassword(p.Password)
	if err != nil {
		return err
	}

	err = validateEmail(p.Email)
	return err
}

func (u *UserService) Register(w http.ResponseWriter, r *http.Request) {
	params := &UserRegisterParams{}
	err := json.NewDecoder(r.Body).Decode(params)
	if err != nil {
		handleUnprocError(errors.New("could not read params"), w)
		return
	}

	if err := validateRegisterParams(params); err != nil {
		handleUnprocError(err, w)
		return
	}

	passwordDigest := md5.New().Sum([]byte(params.Password))
	newUser := User{
		Email:          params.Email,
		Role:           UserRole,
		Banned:         false,
		PasswordDigest: string(passwordDigest),
		FavoriteCake:   params.FavoriteCake,
		BanHistory:     BanHistory{},
	}

	err = u.repository.Add(params.Email, newUser)
	if err != nil {
		handleUnprocError(err, w)
		return
	}
	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write([]byte("registered"))
	u.notifier <- []byte("registered: " + newUser.Email)
	registeredUsers.Inc()
}

func getCakeHandler(w http.ResponseWriter, _ *http.Request, u User, us UserService) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("[" + u.Email + "], your favourite cake is " + u.FavoriteCake))
	us.notifier <- []byte("cake " + u.FavoriteCake + " is given to " + u.Email)
	cakesGiven.Inc()
}

func updateCakeHandler(w http.ResponseWriter, r *http.Request, u User, us UserService) {
	params := &UserRegisterParams{}
	err := json.NewDecoder(r.Body).Decode(params)
	if err != nil {
		handleUnprocError(errors.New("could not read params"), w)
		return
	}

	if err := validateFavoriteCake(params.FavoriteCake); err != nil {
		handleUnprocError(err, w)
		return
	}

	passwordDigest := string(md5.New().Sum([]byte(params.Password)))

	if params.Email != u.Email || passwordDigest != u.PasswordDigest {
		handleUnauthError(errors.New("unauthorized"), w)
		return
	}

	updatedUser := User{
		Email:          params.Email,
		PasswordDigest: passwordDigest,
		FavoriteCake:   params.FavoriteCake,
	}

	err = us.repository.Update(params.Email, updatedUser)
	if err != nil {
		handleUnprocError(err, w)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("favorite cake updated"))
	us.notifier <- []byte(u.Email + " has updated favorite cake")
}

func updateEmailHandler(w http.ResponseWriter, r *http.Request, u User, us UserService) {
	params := &UserRegisterParams{}
	err := json.NewDecoder(r.Body).Decode(params)
	if err != nil {
		handleUnprocError(errors.New("could not read params"), w)
		return
	}

	if err := validateEmail(params.Email); err != nil {
		handleUnprocError(err, w)
		return
	}

	passwordDigest := string(md5.New().Sum([]byte(params.Password)))

	if params.FavoriteCake != u.FavoriteCake || passwordDigest != u.PasswordDigest {
		handleUnauthError(errors.New("unauthorized"), w)
		return
	}

	updatedUser := User{
		Email:          params.Email,
		PasswordDigest: passwordDigest,
		FavoriteCake:   params.FavoriteCake,
	}

	err = us.repository.Add(updatedUser.Email, updatedUser)
	if err != nil {
		handleUnprocError(err, w)
		return
	}

	_, err = us.repository.Delete(u.Email)
	if err != nil {
		handleUnprocError(err, w)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("email updated"))
	us.notifier <- []byte(u.Email + " has updated email")
}

func updatePasswordHandler(w http.ResponseWriter, r *http.Request, u User, us UserService) {
	params := &UserRegisterParams{}
	err := json.NewDecoder(r.Body).Decode(params)
	if err != nil {
		handleUnprocError(errors.New("could not read params"), w)
		return
	}

	if err := validatePassword(params.Password); err != nil {
		handleUnprocError(err, w)
		return
	}

	passwordDigest := string(md5.New().Sum([]byte(params.Password)))

	if params.Email != u.Email || params.FavoriteCake != u.FavoriteCake {
		handleUnauthError(errors.New("unauthorized"), w)
		return
	}

	updatedUser := User{
		Email:          params.Email,
		PasswordDigest: passwordDigest,
		FavoriteCake:   params.FavoriteCake,
	}

	err = us.repository.Update(params.Email, updatedUser)
	if err != nil {
		handleUnprocError(err, w)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("password updated"))
	us.notifier <- []byte(u.Email + " has updated password")
}

func handleUnprocError(err error, w http.ResponseWriter) {
	handleError(err, 422, w)
}

func handleUnauthError(err error, w http.ResponseWriter) {
	handleError(err, 401, w)
}

func handleError(err error, status int, w http.ResponseWriter) {
	w.WriteHeader(status)
	_, _ = w.Write([]byte(err.Error()))
}
