package main

import (
	"context"
	"crypto/md5"
	"github.com/gorilla/mux"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"
)

func wrapJwt(jwt *JWTService, f func(http.ResponseWriter, *http.Request, *JWTService)) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		f(rw, r, jwt)
	}
}

func createEnvVars() {
	_ = os.Setenv("CAKE_SUPERADMIN_EMAIL", "supadmin@mail.com")
	_ = os.Setenv("CAKE_SUPERADMIN_PASSWORD", "IamSuperadmin")
	_ = os.Setenv("CAKE_SUPERADMIN_CAKE", "bestManCake")
}

func processEnvVars(us *UserService) {
	passwordDigest := md5.New().Sum([]byte(os.Getenv("CAKE_SUPERADMIN_PASSWORD")))
	supadmin := User{
		Email:          os.Getenv("CAKE_SUPERADMIN_EMAIL"),
		Role:           SuperAdminRole,
		Banned:         false,
		PasswordDigest: string(passwordDigest),
		FavoriteCake:   os.Getenv("CAKE_SUPERADMIN_CAKE"),
		BanHistory:     BanHistory{},
	}
	_ = us.repository.Add(supadmin.Email, supadmin)
}

func newRouter(us *UserService, jwtService *JWTService) *mux.Router {
	createEnvVars()
	r := mux.NewRouter()

	go runPublisher(us.notifier)
	go startProm()

	r.HandleFunc("/user/register", us.Register).Methods(http.MethodPost)
	r.HandleFunc("/user/jwt", wrapJwt(jwtService, us.JWT)).Methods(http.MethodPost)
	r.HandleFunc("/user/me", jwtService.jwtAuth(*us, getCakeHandler)).Methods(http.MethodGet)
	r.HandleFunc("/user/favorite_cake", jwtService.jwtAuth(*us, updateCakeHandler)).Methods(http.MethodPut)
	r.HandleFunc("/user/email", jwtService.jwtAuth(*us, updateEmailHandler)).Methods(http.MethodPut)
	r.HandleFunc("/user/password", jwtService.jwtAuth(*us, updatePasswordHandler)).Methods(http.MethodPut)
	r.HandleFunc("/admin/ban", jwtService.jwtAuthAdmin(*us, banHandler)).Methods(http.MethodPost)
	r.HandleFunc("/admin/unban", jwtService.jwtAuthAdmin(*us, unbanHandler)).Methods(http.MethodPost)
	r.HandleFunc("/admin/inspect", jwtService.jwtAuthAdmin(*us, inspectHandler)).Methods(http.MethodGet)
	r.HandleFunc("/admin/promote", jwtService.jwtAuthSuperAdmin(*us, promoteHandler)).Methods(http.MethodPost)
	r.HandleFunc("/admin/fire", jwtService.jwtAuthSuperAdmin(*us, fireHandler)).Methods(http.MethodPost)
	processEnvVars(us)
	return r
}

func newLoggingRouter(us *UserService, jwtService *JWTService) *mux.Router {
	createEnvVars()
	r := mux.NewRouter()

	go runPublisher(us.notifier)
	go startProm()

	r.HandleFunc("/user/register", logRequest(us.Register)).Methods(http.MethodPost)
	r.HandleFunc("/user/jwt", logRequest(wrapJwt(jwtService, us.JWT))).Methods(http.MethodPost)
	r.HandleFunc("/user/me", logRequest(jwtService.jwtAuth(*us, getCakeHandler))).Methods(http.MethodGet)
	r.HandleFunc("/user/favorite_cake", logRequest(jwtService.jwtAuth(*us, getCakeHandler))).Methods(http.MethodPut)
	r.HandleFunc("/user/email", logRequest(jwtService.jwtAuth(*us, updateEmailHandler))).Methods(http.MethodPut)
	r.HandleFunc("/user/password", logRequest(jwtService.jwtAuth(*us, updatePasswordHandler))).Methods(http.MethodPut)
	r.HandleFunc("/admin/ban", logRequest(jwtService.jwtAuthAdmin(*us, banHandler))).Methods(http.MethodPost)
	r.HandleFunc("/admin/unban", logRequest(jwtService.jwtAuthAdmin(*us, unbanHandler))).Methods(http.MethodPost)
	r.HandleFunc("/admin/inspect", logRequest(jwtService.jwtAuthAdmin(*us, inspectHandler))).Methods(http.MethodGet)
	r.HandleFunc("/admin/promote", logRequest(jwtService.jwtAuthSuperAdmin(*us, inspectHandler))).Methods(http.MethodPost)
	r.HandleFunc("/admin/fire", logRequest(jwtService.jwtAuthSuperAdmin(*us, fireHandler))).Methods(http.MethodPost)
	processEnvVars(us)
	return r
}

func main() {
	users := NewInMemoryUserStorage()
	userService := UserService{repository: users, notifier: make(chan []byte)}

	jwtService, jwtErr := NewJWTService("pubkey.rsa", "privkey.rsa")
	if jwtErr != nil {
		panic(jwtErr)
	}

	r := newLoggingRouter(&userService, jwtService)

	srv := http.Server{
		Addr:    ":8080",
		Handler: r,
	}

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)
	go func() {
		<-interrupt
		ctx, cancel := context.WithTimeout(context.Background(),
			5*time.Second)
		defer cancel()
		err := srv.Shutdown(ctx)
		if err != nil {
			return
		}
	}()
	log.Println("Server started, hit Ctrl+C to stop")
	err := srv.ListenAndServe()
	if err != nil {
		log.Println("Server exited with error:", err)
	}
	log.Println("Good bye :)")
}
