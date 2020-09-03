package sso

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/zzerroo/zauth"
	"github.com/zzerroo/zauth/util"
)

type casSSO struct {
	engine  zauth.Engine
	session zauth.Session
	ssoHost string
}

type session struct {
}

type sessionInfo struct {
	tgt string
	u   *zauth.UsrInfo
}

func init() {
	zauth.RegisterAuth(zauth.SSOAuth, &casSSO{})
}

// Open ...
func (c *casSSO) Open(engineURI, sessionURI, ssoHost string) error {
	if c.engine == nil || c.session == nil {
		return errors.New("")
	}

	erro := c.engine.Open(engineURI)
	if erro != nil {
		return erro
	}

	erro = c.session.Open(sessionURI)
	if erro != nil {
		return erro
	}

	if -1 == strings.Index(ssoHost, "http://") {
		ssoHost = "http://" + ssoHost
	}
	c.ssoHost = ssoHost
	return nil
}

// InitTable ...
func (c *casSSO) Init(engine zauth.Engine, session zauth.Session) error {
	if engine == nil || session == nil {
		return zauth.ErrorNullPointer
	}

	c.engine = engine
	c.session = session
	return nil
}

func (c *casSSO) getQueryMap(r *http.Request) (url.Values, error) {
	queryMap := make(map[string][]string)

	if r.Method == http.MethodGet {
		queryMap = map[string][]string(r.URL.Query())
	} else if r.Method == http.MethodPost {
		contentType := r.Header.Get("Content-Type")
		if contentType == "application/x-www-form-urlencoded" {
			if erro := r.ParseForm(); erro != nil {
				return nil, erro
			}
			queryMap = r.Form
		} else if strings.Index(contentType, "multipart/form-data") != -1 {
			if erro := r.ParseMultipartForm(2048); erro != nil {
				return nil, erro
			}

			queryMap = r.PostForm
		}
	}

	return queryMap, nil
}

func (c *casSSO) getQueryValue(r *http.Request, key string, idx int) (string, error) {
	if r == nil {
		return "", zauth.ErrorInputParam
	}

	queryMap := make(map[string][]string)
	var t []string
	var ok bool

	if r.Method == http.MethodGet {
		queryMap = map[string][]string(r.URL.Query())
	} else if r.Method == http.MethodPost {
		contentType := r.Header.Get("Content-Type")
		if contentType == "application/x-www-form-urlencoded" {
			if erro := r.ParseForm(); erro != nil {
				return "", erro
			}
			queryMap = r.Form
		} else if strings.Index(contentType, "multipart/form-data") != -1 {
			if erro := r.ParseMultipartForm(2048); erro != nil {
				return "", erro
			}

			queryMap = r.PostForm
		}
	}

	if t, ok = queryMap[key]; !ok {
		return "", zauth.ErrorItemNotFound
	}

	if len(t) > idx {
		return t[idx], nil
	}

	return "", zauth.ErrorItemsLen
}

// Register ...
func (c *casSSO) Register(r *http.Request) error {
	if c.engine == nil {
		return zauth.ErrorNullPointer
	}

	flag, erro := c.getQueryValue(r, zauth.Flag, 0)
	if erro != nil {
		return erro
	}

	name, erro := c.getQueryValue(r, zauth.Name, 0)
	if erro != nil {
		return erro
	}

	pswd, erro := c.getQueryValue(r, zauth.Passwd, 0)
	if erro != nil {
		return erro
	}

	iv, erro := util.UUID()
	if erro != nil {
		return erro
	}

	u := zauth.UsrInfo{}
	u.Pswd.String = pswd
	u.IV.String = iv

	if flag == zauth.FlagName {
		u.Name.String = name
	} else if flag == zauth.FlagEamil {
		u.Email.String = name
	} else if flag == zauth.FlagPhone {
		u.Phone.String = name
	}

	return c.engine.Register(&u)
}

func (c *casSSO) getRedirect(service, ticket string) string {
	if -1 == strings.Index(service, "?") {
		service = fmt.Sprintf("%s?%s=%s", service, zauth.Ticket, ticket)
	} else {
		service = fmt.Sprintf("%s&%s=%s", service, zauth.Ticket, ticket)
	}

	return service
}

func (c *casSSO) redirect(w http.ResponseWriter, r *http.Request, service, ticket string) {
	if -1 == strings.Index(service, "?") {
		service = fmt.Sprintf("%s?%s=%s", service, zauth.Ticket, ticket)
	} else {
		service = fmt.Sprintf("%s&%s=%s", service, zauth.Ticket, ticket)
	}

	http.Redirect(w, r, service, http.StatusFound)
	return
}

func (c *casSSO) AlreadyLogIn(r *http.Request) (string, error) {
	tgcCk, erro := r.Cookie(zauth.TGCCookieName)
	// no cookie
	if erro != nil {
		return "", erro
	}

	// the cookie is nil
	if tgcCk == nil {
		return "", zauth.ErrorItemNotFound
	}

	tgc := tgcCk.Value

	// check whether the tgc-tgt pair exist
	_, erro = c.session.Get(tgc)
	if erro != nil {
		return "", erro
	}

	return tgc, nil
}

func (c *casSSO) firstLogin(querys url.Values) bool {
	_, ok1 := querys[zauth.Name]
	_, ok2 := querys[zauth.Passwd]
	_, ok3 := querys[zauth.Flag]

	if ok1 && ok2 && ok3 {
		return false
	}

	return true
}

func (c *casSSO) LogIn(w http.ResponseWriter, r *http.Request) (info string, erro error) {
	var name, pswd, flag, service, tgt, ticket string

	querys, erro := c.getQueryMap(r)
	if erro != nil {
		return
	}

	if _, ok := querys[zauth.Service]; ok {
		service = querys[zauth.Service][0]
	}

	// check whether the user has logged in
	tgc, erro := c.AlreadyLogIn(r)
	if erro == nil { //already logged in, create a new ticket
		// create a new ticket
		ticket, erro = util.CreateTk(util.HMAC, tgc)
		if erro != nil {
			return
		}

		info = c.getRedirect(service, ticket)
		return info, zauth.ErrorNeedRedirect
	}

	bLogin := c.firstLogin(querys)

	// first login,return login form
	if bLogin == true {
		info = fmt.Sprintf(zauth.LoginTemplate, c.ssoHost+"/login?step=1&service="+service)
		return info, zauth.ErrorNeedShowForm
	}

	// check the login info
	if _, ok := querys[zauth.Name]; ok {
		name = querys[zauth.Name][0]
	}

	if _, ok := querys[zauth.Passwd]; ok {
		pswd = querys[zauth.Passwd][0]
	}

	if _, ok := querys[zauth.Flag]; ok {
		flag = querys[zauth.Flag][0]
	}

	u, erro := c.engine.LogIn(name, pswd, flag)
	if erro != nil {
		return
	}

	u.Pswd.String = ""
	seInfo := &sessionInfo{tgt, u}

	//create tgt
	tgt, erro = util.UUID()
	if erro != nil {
		return
	}
	//create tgc
	tgc, erro = util.UUID()
	if erro != nil {
		return
	}

	//set the tgc-tgt pair to session, the default cookie time is 5mins
	erro = c.session.Set(tgc, seInfo, 300*time.Second)
	if erro != nil {
		return
	}

	// create the ticket,use tgc as key
	ticket, erro = util.CreateTk(util.HMAC, tgc)
	if erro != nil {
		c.session.Delete(tgc)
		return
	}

	tgcCk := &http.Cookie{
		Name:     zauth.TGCCookieName,
		Value:    tgc,
		Domain:   r.URL.Host,
		Path:     "/",
		Expires:  time.Now().Add(60 * 60 * time.Second),
		HttpOnly: true,
	}
	http.SetCookie(w, tgcCk)

	info = c.getRedirect(service, ticket)
	return
}

// LogIn ...
// func (c *casSSO) LogIn2(w http.ResponseWriter, r *http.Request) error {
// 	var name, pswd, flag, service, tgt, ticket string
// 	querys, erro := c.getQueryMap(r)
// 	if erro != nil {
// 		return erro
// 	}

// 	if _, ok := querys[zauth.Service]; !ok {
// 		return zauth.ErrorItemNotFound
// 	}
// 	service = querys[zauth.Service][0]

// 	// check to show the login form
// 	_, erro = c.getQueryValue(r, zauth.Step, 0)
// 	if erro != nil {
// 		if erro == zauth.ErrorItemNotFound {
// 			sF := fmt.Sprintf(zauth.LoginTemplate, c.ssoHost+"/login?step=1&service="+service)
// 			w.Write(util.String2Byte(sF))
// 			return nil
// 		}

// 		return erro
// 	}

// 	// check the cookie for tgc, if the paired tgt exist in the session,then return
// 	// otherwise the user has not logined in
// 	tgc, erro := c.IsLogIn(r)
// 	if erro == nil { // already login, create a new ticket,move to client server
// 		// create a new ticket
// 		ticket, erro = util.CreateTk(util.HMAC, tgc)
// 		if erro != nil {
// 			return erro
// 		}

// 		erro = c.redirect(w, r, service, ticket)
// 		if erro != nil {
// 			return erro
// 		}
// 		return nil
// 	}

// 	// get query param,for name、password、flag、service
// 	name, erro = c.getQueryValue(r, zauth.Name, 0)
// 	if erro != nil {
// 		return erro
// 	}

// 	pswd, erro = c.getQueryValue(r, zauth.Passwd, 0)
// 	if erro != nil {
// 		return erro
// 	}

// 	flag, erro = c.getQueryValue(r, zauth.Flag, 0)
// 	if erro != nil {
// 		return erro
// 	}

// 	_, erro = c.engine.LogIn(name, pswd, flag)
// 	if erro != nil {
// 		return erro
// 	}

// 	//create tgt
// 	tgt, erro = util.UUID()
// 	if erro != nil {
// 		return zauth.ErrorLogIn
// 	}
// 	//create tgc
// 	tgc, erro = util.UUID()
// 	if erro != nil {
// 		return erro
// 	}

// 	//set the tgc-tgt pair to session, the default cookie time is 5mins
// 	erro = c.session.Set(tgc, tgt, 300*time.Second)
// 	if erro != nil {
// 		return zauth.ErrorAddSession
// 	}

// 	// create the ticket,use tgc as key
// 	ticket, erro = util.CreateTk(util.HMAC, tgc)
// 	if erro != nil {
// 		c.session.Delete(tgc)
// 		return zauth.ErrorTkCtr
// 	}

// 	tgcCk := &http.Cookie{
// 		Name:     zauth.TGCCookieName,
// 		Value:    tgc,
// 		Domain:   r.URL.Host,
// 		Path:     "/",
// 		Expires:  time.Now().Add(60 * 60 * time.Second),
// 		HttpOnly: true,
// 	}
// 	http.SetCookie(w, tgcCk)

// 	erro = c.redirect(w, r, service, ticket)
// 	if erro != nil {
// 		return erro
// 	}

// 	return nil
// }

// LogOut ...
func (c *casSSO) LogOut(w http.ResponseWriter, r *http.Request) error {
	tgcCk, erro := r.Cookie(zauth.TGCCookieName)
	if erro != nil {
		return erro
	}

	// delete session
	erro = c.session.Delete(tgcCk.Value)
	if erro != nil {
		return erro
	}

	// delete cookie
	tgcCk.MaxAge = -1
	tgcCk.Expires = time.Now().Add(-7 * 24 * time.Hour)
	http.SetCookie(w, tgcCk)
	return nil
}

// CheckTk ...
func (c *casSSO) CheckTk(r *http.Request) (string, error) {
	var ticket string

	querys, erro := c.getQueryMap(r)
	if erro != nil {
		return "", erro
	}

	if _, ok := querys[zauth.Ticket]; ok {
		ticket = querys[zauth.Ticket][0]
	}

	// check the sign
	tgc, erro := util.VerifyTk(ticket)
	if erro != nil {
		return "", erro
	}

	// check the session
	info, erro := c.session.Get(tgc)
	if erro != nil {
		return "", erro
	}

	infoBody, erro := json.Marshal(info)
	if erro != nil {
		return "", erro
	}

	return util.Byte2String(infoBody), nil
}

// CreateTk ...
func (c *casSSO) CreateTk(u *zauth.UsrInfo) {
}

// RefreshTk ...
func (c *casSSO) RefreshTk() {

}
