package sso

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/garyburd/redigo/redis"
	"github.com/zzerroo/zauth"
	"github.com/zzerroo/zauth/util"
)

// casSSO implements sso based on cas
type casSSO struct {
	engine  zauth.Engine
	session zauth.Session
}

type sessionInfo struct {
	TGT string        `json:"-"`
	U   zauth.UsrInfo `json:u`
}

func init() {
	zauth.RegisterAuth(zauth.SSOAuth, &casSSO{})
}

// Open the engine and session, set the init params
func (c *casSSO) Open(engineURI, sessionURI string) error {
	if c.engine == nil || c.session == nil {
		return zauth.ErrorUnknown
	}

	erro := c.engine.Open(engineURI)
	if erro != nil {
		return erro
	}

	erro = c.session.Open(sessionURI)
	if erro != nil {
		return erro
	}

	return nil
}

// Init set engine and session for sso
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
		// get, return the query string map

		queryMap = map[string][]string(r.URL.Query())
	} else if r.Method == http.MethodPost {
		// post(x-www-form-urlencoded), return the form info
		contentType := r.Header.Get("Content-Type")
		if contentType == "application/x-www-form-urlencoded" {
			if erro := r.ParseForm(); erro != nil {
				return nil, erro
			}
			queryMap = r.Form
		} else if strings.Index(contentType, "multipart/form-data") != -1 {
			// post(multipart/form-data), return the PostForm
			if erro := r.ParseMultipartForm(2048); erro != nil {
				return nil, erro
			}

			queryMap = r.PostForm
		}
	}

	return queryMap, nil
}

func (c *casSSO) getRedirect(service, ticket string) string {
	if -1 == strings.Index(service, "?") {
		service = fmt.Sprintf("%s?%s=%s", service, zauth.Ticket, ticket)
	} else {
		service = fmt.Sprintf("%s&%s=%s", service, zauth.Ticket, ticket)
	}

	return service
}

func (c *casSSO) alreadyLogIn(r *http.Request) (string, error) {
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

// LogIn is responsible for:
//	if the user has logged in, refresh and create a new ticket then return
//	if the user has not logged in, show the login form
//	else check the user info
// Return Value:
//	info:
//		when ErrorNeedRedirect, the redirect url
//		others, no use
//	erro:
//		ErrorNeedRedirect, need redirect to the pages indicated by the service param
//		ErrorNeedShowForm, need show the login form
//		other error, errors
//		nil, ok
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
	tgc, erro := c.alreadyLogIn(r)
	if erro == nil {
		//already logged in, create a new ticket
		// for security reason, every ticket will only be used for one time

		// create a new ticket
		ticket, erro = util.CreateTk(util.HMAC, tgc)
		if erro != nil {
			return
		}

		// accord the service param, create the redirect url
		//	if the req like this, ...xxx?service=http://abcd, the redirect url will be http://abcd&ticket=yyyy
		info = c.getRedirect(service, ticket)
		return info, zauth.ErrorNeedRedirect
	}

	// if there is no name、pswd、flag in the query map，show the login form
	//	most of time, a http get request can indicate a new login
	//	but consider the C/S, check param will be the best way
	bLogin := c.firstLogin(querys)
	host := util.GetReqHost(r)

	// change to template later 2020年10月21日
	if bLogin == true {
		info = fmt.Sprintf(zauth.LoginTemplate, host+"/login?step=1&service="+service, host+"/register")
		return info, zauth.ErrorNeedShowForm
	}

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

	//create a new tgt
	tgt, erro = util.UUID()
	if erro != nil {
		return
	}
	//create the pair tgc
	tgc, erro = util.UUID()
	if erro != nil {
		return
	}

	// store the tgt:user pair info to the session
	//	when the ticket is checked, the service get the user info
	seInfo := sessionInfo{tgt, *u}
	s, erro := json.Marshal(seInfo)
	if erro != nil {
		return
	}

	//set the tgc-tgt pair to session, the default cookie time is 5mins
	erro = c.session.Set(tgc, s, 300*time.Second)
	if erro != nil {
		return
	}

	// create the ticket, use tgc as key
	ticket, erro = util.CreateTk(util.HMAC, tgc)
	if erro != nil {
		c.session.Delete(tgc)
		return
	}

	tgcCk := &http.Cookie{
		Name:     zauth.TGCCookieName,
		Value:    tgc,
		Path:     "/",
		Expires:  time.Now().Add(60 * 60 * time.Second),
		HttpOnly: true,
	}
	http.SetCookie(w, tgcCk)

	info = c.getRedirect(service, ticket)
	return
}

// Register check the info, show the register form, or do the register action
// Return Value:
//	info, when ErrorNeedShowForm, indicate the register from
//	other, no use
// error:
//	ErrorNeedShowForm, the info param is the login form
//	other error or nil
func (c *casSSO) Register(r *http.Request) (info string, erro error) {
	host := util.GetReqHost(r)
	if r.Method == http.MethodGet {
		info = fmt.Sprintf(zauth.RegisterTemplate, host+"/register")
		erro = zauth.ErrorNeedShowForm
		return
	}

	var email, pswd1, pswd2 string
	var ok bool

	querys, erro := c.getQueryMap(r)
	if erro != nil {
		return
	}

	if _, ok = querys[zauth.EMail]; ok {
		email = querys[zauth.EMail][0]
	}

	if _, ok = querys[zauth.Passwd1]; ok {
		pswd1 = querys[zauth.Passwd1][0]
	}

	if _, ok = querys[zauth.Passwd2]; ok {
		pswd1 = querys[zauth.Passwd2][0]
	}

	// check the email pattern
	if erro = util.CheckEmail(email); erro != nil {
		return
	}

	// check the password pattern
	//	at least  8 characters, at least inlucde 3 kinds of num、characters(captical、low)、special characters
	if erro = util.CheckPsswd(pswd1); erro != nil {
		return
	}

	if pswd1 != pswd2 {
		erro = zauth.ErrorInputParam
	}

	iv, erro := util.UUID()
	if erro != nil {
		return
	}

	u := zauth.UsrInfo{}
	u.Name = email
	u.Email = email
	u.Phone = email
	u.Pswd = pswd1
	u.IV = iv

	erro = c.engine.Register(&u)
	return
}

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

// CheckTk check the ticket and get the ticket info
// Return Value:
//		string: the ticket(user) info
//		error:
func (c *casSSO) CheckTk(r *http.Request) (string, error) {
	var ticket string

	querys, erro := c.getQueryMap(r)
	if erro != nil {
		return "", erro
	}

	if _, ok := querys[zauth.Ticket]; ok {
		ticket = querys[zauth.Ticket][0]
	}

	// check wheather the ticket is validate accord to the format of the ticket
	//	see VerifyTk in util.go
	tgc, erro := util.VerifyTk(ticket)
	if erro != nil {
		return "", erro
	}

	// check wheather there is a session,  this is for replay attacks
	info, erro := redis.Bytes(c.session.Get(tgc))
	if erro != nil {
		return "", erro
	}

	var s sessionInfo
	erro = json.Unmarshal(info, &s)
	if erro != nil {
		return "", erro
	}

	u, erro := json.Marshal(s.U)
	if erro != nil {
		return "", erro
	}
	return util.Byte2String(u), nil
}

// RefreshTk no use, this is for oauth2.0
func (c *casSSO) RefreshTk() {
}
