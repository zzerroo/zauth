package main

import (
	"log"
	"net/http"

	"github.com/zzerroo/zauth"
	_ "github.com/zzerroo/zauth/engine/mysql"
	_ "github.com/zzerroo/zauth/session/redis"
	_ "github.com/zzerroo/zauth/sso"
)

var auth zauth.Auth
var erro error

// func TestSSOServer(t *testing.T) {
// 	auth, erro = zauth.Use(zauth.SSOAuth, zauth.MySqlEngine, zauth.CacheRedis)
// 	if erro != nil {
// 		log.Fatalf("error zauth use,info:" + erro.Error())
// 	}
// 	auth.Open("root:zyx1987@tcp(117.51.159.208:3306)/auth?charset=utf8", "redis://:zyx1987@117.51.159.208:/?active=21&idle=15&itimeout=2")

// 	http.HandleFunc("/login", loginServerSSO)
// 	http.HandleFunc("/register", register)
// 	http.HandleFunc("/check", check)
// 	log.Fatal(http.ListenAndServe("0.0.0.0:8080", nil))
// }

func main() {
	auth, erro = zauth.Use(zauth.SSOAuth, zauth.MySqlEngine, zauth.CacheRedis)
	if erro != nil {
		log.Fatalf("error zauth use,info:" + erro.Error())
	}
	auth.Open("root:zyx1987@tcp(117.51.159.208:3306)/auth?charset=utf8", "redis://:zyx1987@117.51.159.208:/?active=21&idle=15&itimeout=2")

	http.HandleFunc("/login", loginServerSSO)
	http.HandleFunc("/register", register)
	http.HandleFunc("/check", check)
	log.Fatal(http.ListenAndServe("0.0.0.0:8081", nil))
}

func loginServerSSO(w http.ResponseWriter, r *http.Request) {
	erro = auth.LogIn(w, r)
	if erro != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}

	w.WriteHeader(http.StatusOK)
}

func register(w http.ResponseWriter, r *http.Request) {
	erro := auth.Register(r)
	if erro != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}

	w.WriteHeader(http.StatusOK)
}

func check(w http.ResponseWriter, r *http.Request) {
	erro := auth.CheckTk(r)
	if erro != nil {
		w.WriteHeader(http.StatusBadRequest)
	}

	w.WriteHeader(http.StatusOK)
}
