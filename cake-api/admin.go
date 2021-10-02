package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

type Role int8

const (
	UserRole Role = iota
	AdminRole
	SuperAdminRole
)

type UserBanParams struct {
	Email  string `json:"email"`
	Reason string `json:"reason"`
}

type EmailParams = struct {
	Email string `json:"email"`
}

type UserUnbanParams = EmailParams

type BanHistoryQuery struct {
	Executor string
	IsBan    bool
	Time     time.Time
	Reason   string
}

const banTimeFormat = "02 January 2006 01:02:03"

type BanHistory []BanHistoryQuery

func banHandler(w http.ResponseWriter, r *http.Request, executor User, users UserRepository) {
	params := &UserBanParams{}
	err := json.NewDecoder(r.Body).Decode(params)
	if err != nil {
		handleUnprocError(errors.New("could not read params"), w)
		return
	}

	if err := validateEmail(params.Email); err != nil {
		handleUnprocError(err, w)
		return
	}

	user, getErr := users.Get(params.Email)
	if getErr != nil {
		handleUnprocError(getErr, w)
		return
	}

	if executor.Role <= user.Role {
		handleUnauthError(errors.New("permission denied"), w)
		return
	}

	banHistoryQuery := BanHistoryQuery{
		Executor: executor.Email,
		IsBan:    true,
		Time:     time.Now(),
		Reason:   params.Reason,
	}
	user.Banned = true
	user.BanHistory = append(user.BanHistory, banHistoryQuery)

	err = users.Update(user.Email, user)
	if err != nil {
		handleUnprocError(err, w)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("user " + user.Email + " banned"))
}

func unbanHandler(w http.ResponseWriter, r *http.Request, executor User, users UserRepository) {
	params := &UserUnbanParams{}
	err := json.NewDecoder(r.Body).Decode(params)
	if err != nil {
		handleUnprocError(errors.New("could not read params"), w)
		return
	}

	if err := validateEmail(params.Email); err != nil {
		handleUnprocError(err, w)
		return
	}

	user, getErr := users.Get(params.Email)
	if getErr != nil {
		handleUnprocError(getErr, w)
		return
	}

	if executor.Role <= user.Role {
		handleUnauthError(errors.New("permission denied"), w)
		return
	}

	banHistoryQuery := BanHistoryQuery{
		Executor: executor.Email,
		IsBan:    false,
		Time:     time.Now(),
		Reason:   "",
	}
	user.Banned = false
	user.BanHistory = append(user.BanHistory, banHistoryQuery)

	err = users.Update(user.Email, user)
	if err != nil {
		handleUnprocError(err, w)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("user " + user.Email + " unbanned"))
}

func inspectHandler(w http.ResponseWriter, r *http.Request, _ User, users UserRepository) {
	email := r.URL.Query().Get("email")

	user, getErr := users.Get(email)
	if getErr != nil {
		handleUnprocError(getErr, w)
		return
	}

	banHistoryStr := ""
	for _, query := range user.BanHistory {
		banStr := ""
		if query.IsBan {
			banStr = "banned (reason: " + query.Reason + ")"
		} else {
			banStr = "unbanned"
		}
		banHistoryStr += "-- was " + banStr + " at " +
			query.Time.Format(banTimeFormat) +
			" by " + query.Executor + "\n"
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("user " + user.Email + ":\n" + banHistoryStr))
}

func promoteHandler(w http.ResponseWriter, r *http.Request, _ User, users UserRepository) {
	params := &EmailParams{}
	err := json.NewDecoder(r.Body).Decode(params)
	if err != nil {
		handleUnprocError(errors.New("could not read params"), w)
		return
	}
	user, getErr := users.Get(params.Email)
	if getErr != nil {
		handleUnprocError(getErr, w)
		return
	}

	user.Role = AdminRole
	err = users.Update(user.Email, user)
	if err != nil {
		handleUnprocError(err, w)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("user " + user.Email + " promoted to admin"))
}

func fireHandler(w http.ResponseWriter, r *http.Request, _ User, users UserRepository) {
	params := &EmailParams{}
	err := json.NewDecoder(r.Body).Decode(params)
	if err != nil {
		handleUnprocError(errors.New("could not read params"), w)
		return
	}
	user, getErr := users.Get(params.Email)
	if getErr != nil {
		handleUnprocError(getErr, w)
		return
	}

	user.Role = UserRole
	err = users.Update(user.Email, user)
	if err != nil {
		handleUnprocError(err, w)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("admin " + user.Email + " downgraded to user"))
}
