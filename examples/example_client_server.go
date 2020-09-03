package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/zzerroo/zauth"
	zRedis "github.com/zzerroo/zauth/session/redis"
	zUtil "github.com/zzerroo/zauth/util"
)

const ssoServer = "http://127.0.0.1:8081/"

var ssoServerLogin = ssoServer + "login?service="
var ssoServerCheckTicket = ssoServer + "check?ticket="
var session *zRedis.Redis = &zRedis.Redis{}

var errorNoTicket = errors.New("error no ticket")
var errorNoSession = errors.New("error no session")

type myHandler struct{}

// ServeHTTP check the request url,
//	if the url contains a ticket,then verify the ticket
//	otherwise check whether there is a session
func (m *myHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// check whether the url contains ticket
	erro := m.checkTicket(w, r)
	if erro == errorNoTicket {

		// check whether the user has logged in
		retInfo, erro := m.checkLogin(r)
		if erro == errorNoSession {

			// no login  redirect to the login form
			http.Redirect(w, r, retInfo, http.StatusTemporaryRedirect)
			return
		}
	} else if erro != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	path := r.URL.Path
	switch path {
	case "/hello":
		hello(w, r)
	default:
		hello(w, r)
	}
}

func main() {
	erro := session.Open("redis://:xxxx@127.0.0.1:/?active=21&idle=15&itimeout=2")
	if erro != nil {
		log.Fatal("error open redis session,for :" + erro.Error())
	}

	handler := myHandler{}
	log.Fatal(http.ListenAndServe("0.0.0.0:8080", &handler))
}

func (m *myHandler) checkLogin(r *http.Request) (string, error) {
	// get the full request url,include scheme,host,request uri
	reqUrl := zUtil.GetReqURL(r)

	// check the session(cookie) to verify whether the user has logged in
	sessionid, erro := r.Cookie("sessionid")
	if erro == http.ErrNoCookie {
		return ssoServerLogin + reqUrl, errorNoSession
	}

	// check if there is a validate session
	_, erro = session.Get(sessionid)
	if erro != nil {
		return ssoServerLogin + reqUrl, errorNoSession
	}

	return "", nil
}

func (m *myHandler) checkTicket(w http.ResponseWriter, r *http.Request) error {
	// check whether the ticket
	//	if the ticket param exist then verify the ticket from sso server
	//	if the ticket is validate ticket, write a cookie
	querys := r.URL.Query()
	if ticket, ok := querys[zauth.Ticket]; ok {
		resp, erro := http.Get(ssoServerCheckTicket + ticket[0])
		if erro != nil {
			return erro
		}

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("error unkown")
		}

		key, _ := zUtil.UUID()
		value, _ := zUtil.UUID()
		session.Set(key, value, 30*60*time.Second)

		sessionCk := &http.Cookie{
			Name:     "sessionid",
			Value:    key,
			Domain:   r.URL.Host,
			Path:     "/",
			Expires:  time.Now().Add(60 * 60 * time.Second),
			HttpOnly: true,
		}
		http.SetCookie(w, sessionCk)
		return nil
	}

	return errorNoTicket
}

func hello(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("hello"))
	return
}
