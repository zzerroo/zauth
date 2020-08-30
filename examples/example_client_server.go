package main

import (
	"log"
	"net/http"
	"time"

	"github.com/zzerroo/zauth"
	zRedis "github.com/zzerroo/zauth/session/redis"
	zUtil "github.com/zzerroo/zauth/util"
)

const ssoServer = "http://127.0.0.1:8081/"

var ssoServerLogin = ssoServer + "login?service=http://127.0.0.1:8080/"
var ssoServerCheckTicket = ssoServer + "check"

var session *zRedis.Redis = &zRedis.Redis{}

// func TestClientServer(t *testing.T) {
// 	erro := session.Open("redis://:zyx1987@117.51.159.208:/?active=21&idle=15&itimeout=2")
// 	if erro != nil {
// 		log.Fatal("error open redis session,for :" + erro.Error())
// 	}

// 	http.HandleFunc("login", loginServer)
// 	http.ListenAndServe("0.0.0.0:8081", nil)
// }

func main() {
	erro := session.Open("redis://:zyx1987@117.51.159.208:/?active=21&idle=15&itimeout=2")
	if erro != nil {
		log.Fatal("error open redis session,for :" + erro.Error())
	}

	http.HandleFunc("/login", loginServer)
	http.HandleFunc("/ticket", checkTicket)
	log.Fatal(http.ListenAndServe("0.0.0.0:8080", nil))
}

func loginServer(w http.ResponseWriter, r *http.Request) {
	// check the session(cookie) to verify whether the user has login
	sessionid, erro := r.Cookie("sessionid")

	// no cookie
	if erro == http.ErrNoCookie {
		http.Redirect(w, r, ssoServerLogin, http.StatusTemporaryRedirect)
		return
	}

	// check the session
	_, erro = session.Get(sessionid)
	if erro != nil {
		http.Redirect(w, r, ssoServerLogin, http.StatusTemporaryRedirect)
		return
	}

	w.WriteHeader(http.StatusInternalServerError)
	return
}

func checkTicket(w http.ResponseWriter, r *http.Request) {
	// check whether the ticket exist
	//	if exist then verify the ticket from sso server
	//	if not exist then
	//		check the session(cookie) if not exist redirect to sso server to login
	querys := r.URL.Query()
	if _, ok := querys[zauth.Ticket]; ok {
		resp, erro := http.Get(ssoServerCheckTicket)
		if erro != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if resp.StatusCode != http.StatusOK {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		key, _ := zUtil.UUID()
		value, _ := zUtil.UUID()
		session.Set(key, value, 30*60*time.Second)
		w.WriteHeader(http.StatusOK)
		return
	}

	w.WriteHeader(http.StatusInternalServerError)
	return
}
