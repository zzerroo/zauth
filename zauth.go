package zauth

import (
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

// Auth include all auth func
type Auth interface {
	// Open the engine、session and do some init operation
	Open(string, string) error

	// Set the Engine and Session for the implemention of auth
	Init(Engine, Session) error

	// LogIn to the service
	LogIn(http.ResponseWriter, *http.Request) (string, error)

	// LogOut the service
	LogOut(http.ResponseWriter, *http.Request) error

	// CheckTk check the ticket from the service
	CheckTk(*http.Request) (string, error)

	// RefreshTk create a new ticket
	RefreshTk()

	// Register a new user
	Register(*http.Request) (string, error)
}

// Engine is the  data management system, it is be responsible for
//	user info store、query、update and so on
type Engine interface {
	// Open the connections to the server(db)
	Open(string) error
	Register(*UsrInfo) error
	LogIn(string, string, string) (*UsrInfo, error)
	GetUsrInfo(string, string) (*UsrInfo, error)
}

// Session is the session management
type Session interface {
	Init()
	Open(...interface{}) error
	Set(interface{}, interface{}, time.Duration) error
	Get(interface{}) (interface{}, error)
	Delete(interface{}) error
}

// RegisterAuth register the name:auth pair to the the auth system
//	currently there is only one implemention: zauth.SSOAuth:&casSSO{}
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

// RegisterEngine register the name:engine pair implemention to the auth system
//	currently the map only include zauth.MySqlEngine:&mysql{} implemention
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

// RegisterSession register the name:session pair implemention the auth system
//	there are 2 pairs,zauth.CacheSession:&Cache{}、zauth.CacheRedis, &Redis{}
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

// UnRegister no use
func UnRegister() {
}

// Use declare the used auth type、the engine type、the session type
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

// UsrInfo ...
type UsrInfo struct {
	Name  string `json:name`
	Pswd  string `json:"-"`
	Phone string `json:phone`
	Email string `json:email`
	Other string `json:other`
	IV    string `json:"-"`
}
