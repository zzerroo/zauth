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

func main() {
	auth, erro = zauth.Use(zauth.SSOAuth, zauth.MySqlEngine, zauth.CacheRedis)
	if erro != nil {
		log.Fatalf("error zauth use,info:" + erro.Error())
	}
	auth.Open("root:xxx@tcp(128.0.0.1:3306)/auth?charset=utf8",
		"redis://:xxx@127.0.0.1:/?active=21&idle=15&itimeout=2",
		"http://127.0.0.1:8081")

	http.HandleFunc("/login", loginServerSSO)
	http.HandleFunc("/register", register)
	http.HandleFunc("/check", check)
	log.Fatal(http.ListenAndServe("0.0.0.0:8081", nil))
}

func loginServerSSO(w http.ResponseWriter, r *http.Request) {
	retInfo, erro := auth.LogIn(w, r)
	if erro == zauth.ErrorNeedShowForm { // first,show login from
		w.Write([]byte(retInfo))
		return
	} else if erro == zauth.ErrorNeedRedirect { // the session exist, alerady loged in
		http.Redirect(w, r, retInfo, http.StatusTemporaryRedirect)
		return
	} else if erro != nil {
		w.Write([]byte(erro.Error()))
		return
	}

	// log in successed
	http.Redirect(w, r, retInfo, http.StatusTemporaryRedirect)
	return
}

func register(w http.ResponseWriter, r *http.Request) {
	erro := auth.Register(r)
	if erro != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}

	w.WriteHeader(http.StatusOK)
}

func check(w http.ResponseWriter, r *http.Request) {
	retInfo, erro := auth.CheckTk(r)
	if erro != nil {
		w.Write([]byte(erro.Error()))
	}

	// a validate ticket,return the user info
	w.Write([]byte(retInfo))
	return
}
