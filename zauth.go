package zauth

import (
	"database/sql"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"
	"time"
)

var (
	mut      sync.RWMutex
	auths    = make(map[string]Auth)
	engines  = make(map[string]Engine)
	sessions = make(map[string]Session)
)

// Auth ...
type Auth interface {
	Open(string, string) error
	Init(Engine, Session) error
	LogIn(http.ResponseWriter, *http.Request) error
	LogOut(w http.ResponseWriter, r *http.Request) error
	CheckTk(r *http.Request) error
	CreateTk(*UsrInfo)
	RefreshTk()
	Register(*http.Request) error
}

// Engine ...
type Engine interface {
	Open(string) error
	Register(*UsrInfo) error
	LogIn(string, string, string) (*UsrInfo, error)
	GetUsrInfo(string, string) (*UsrInfo, error)
}

// Session ...
type Session interface {
	Init()
	Open(...interface{}) error
	Set(interface{}, interface{}, time.Duration) error
	Get(interface{}) (interface{}, error)
	Delete(interface{}) error
}

// init ...
func init() {
}

// RegisterAuth ...
func RegisterAuth(name string, auth Auth) {
	mut.Lock()
	defer mut.Unlock()

	if auths == nil {
		panic("auth:Register auth is nil")
	}

	if _, dup := auths[name]; dup {
		panic("auth:Register called twice for driver" + name)
	}

	auths[name] = auth
}

// RegisterEngine ...
func RegisterEngine(name string, engine Engine) {
	mut.Lock()
	defer mut.Unlock()

	if engines == nil {
		panic("engines:Register engines is nil")
	}

	if _, dup := engines[name]; dup {
		panic("auth:Register called twice for driver" + name)
	}

	engines[name] = engine
}

// RegisterSession ...
func RegisterSession(name string, session Session) {
	mut.Lock()
	defer mut.Unlock()

	if session == nil {
		panic("session:Register engines is nil")
	}

	if _, dup := sessions[name]; dup {
		panic("session:Register called twice for driver" + name)
	}

	sessions[name] = session
}

// UnRegister ...
func UnRegister() {

}

// Use ...
func Use(authType, engineType, sessionType string) (Auth, error) {
	var engine Engine
	var auth Auth
	var session Session
	var ok bool

	mut.RLock()
	defer mut.RUnlock()

	if auth, ok = auths[authType]; !ok {
		return nil, ErrorItemNotFound
	}

	if engine, ok = engines[engineType]; !ok {
		return nil, ErrorItemNotFound
	}

	if session, ok = sessions[sessionType]; !ok {
		return nil, ErrorItemNotFound
	}

	auth.Init(engine, session)
	return auth, nil
}

// GetLoginForm ...
func GetLoginForm(host string) ([]byte, error) {
	s, erro := ioutil.ReadFile("./zauth/html/login.html")
	if erro != nil {
		return nil, erro
	}

	sF := fmt.Sprintf(string(s), host)
	return []byte(sF), erro
}

// UsrInfo ...
type UsrInfo struct {
	Name  sql.NullString `db:name`
	Pswd  sql.NullString `db:pswd`
	Phone sql.NullString `db:phone`
	Email sql.NullString `db:email`
	Other sql.NullString `db:other`
	IV    sql.NullString `db:iv`
}
