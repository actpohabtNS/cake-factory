package main

import (
	"flag"
	"github.com/actpohabtNS/cake-factory/jwt"
	"log"
	"net/http"
	"strings"
)

var addr = flag.String("addr", ":8081", "http service address")

func main() {
	flag.Parse()
	hub := NewHub()
	go hub.run()
	go hub.receive()

	jwtService, err := jwt.NewJWTService()
	if err != nil {
		panic(err)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if _, err := jwtService.ParseJWT(token); err != nil {
			w.WriteHeader(401)
			w.Write([]byte("unauthorized"))
			return
		}

		serveWS(hub, w, r)
	})

	err = http.ListenAndServe(*addr, nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
