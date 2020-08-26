package redis

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/zzerroo/zauth"

	redisgo "github.com/garyburd/redigo/redis"
)

// Redis ...
type Redis struct {
	pool *redisgo.Pool
}

// RedisInfo ...
type RedisInfo struct {
	Proto       string
	Host        string
	Port        int
	Psswd       string
	DB          int
	MaxActive   int
	MacxIdle    int
	IdelTimeout int
}

func init() {
	zauth.RegisterSession(zauth.CacheRedis, &Redis{})
}

// NewRedis ...
func NewRedis(redisInfo *RedisInfo) (*Redis, error) {
	r := &Redis{}
	erro := r.Open(redisInfo)
	if erro != nil {
		return nil, erro
	}

	return r, nil
}

// Init no use
func (r *Redis) Init() {
}

func (r *Redis) initPool(redisInfo *RedisInfo) error {
	r.pool = &redisgo.Pool{
		MaxActive:   redisInfo.MaxActive,
		MaxIdle:     redisInfo.MacxIdle,
		IdleTimeout: time.Duration(redisInfo.IdelTimeout) * time.Second,
		Dial: func() (redisgo.Conn, error) {
			uri := fmt.Sprintf("%s:%d", redisInfo.Host, redisInfo.Port)
			options := []redisgo.DialOption{
				redisgo.DialReadTimeout(time.Duration(1000) * time.Millisecond),
				redisgo.DialWriteTimeout(time.Duration(1000) * time.Millisecond),
				redisgo.DialConnectTimeout(time.Duration(1000) * time.Millisecond),
			}

			if len(redisInfo.Psswd) != 0 {
				options = append(options, redisgo.DialPassword(redisInfo.Psswd))
			}

			if redisInfo.DB >= 0 {
				options = append(options, redisgo.DialDatabase(redisInfo.DB))
			}

			return redisgo.Dial(redisInfo.Proto, uri, options...)
		},
	}

	conn := r.pool.Get()
	_, erro := conn.Do("PING")
	if erro != nil {
		return erro
	}

	conn.Close()
	return nil
}

// like redis://user:secret@localhost:6379/0?active=10&idle=5&itimeout=2
func (r *Redis) parseUrl(url string) (RedisInfo, error) {
	var redisInfo RedisInfo
	if len(url) == 0 {
		return redisInfo, zauth.ErrorInputParam
	}

	// begin with redis:
	if ok := strings.HasPrefix(url, "redis:"); !ok {
		return redisInfo, zauth.ErrorInputParam
	}

	schemes := strings.Split(url, "/")
	if len(schemes) != 4 {
		return redisInfo, zauth.ErrorInputParam
	}

	// 0?active=10&idle=5&itimeout=2
	querys := strings.Split(schemes[3], "?")
	if querys[0] == "" {
		redisInfo.DB = 0
	} else {
		d, erro := strconv.Atoi(querys[0])
		if erro != nil {
			return redisInfo, zauth.ErrorInputParam
		}
		redisInfo.DB = d
	}

	params := strings.Split(querys[1], "&")
	for i := 0; i < len(params); i++ {
		pairs := strings.Split(params[i], "=")
		v, erro := strconv.Atoi(pairs[1])
		if erro != nil {
			return redisInfo, zauth.ErrorInputParam
		}

		if pairs[0] == "active" {
			redisInfo.MaxActive = v
		} else if pairs[0] == "idle" {
			redisInfo.MacxIdle = v
		} else if pairs[0] == "itimeout" {
			redisInfo.IdelTimeout = v
		}
	}

	// user:secret@localhost:6379
	psdAndHosts := strings.Split(schemes[2], ":")
	if len(psdAndHosts) != 3 {
		return redisInfo, zauth.ErrorInputParam
	}

	// port
	if psdAndHosts[2] == "" {
		redisInfo.Port = 6379
	} else {
		p, erro := strconv.Atoi(psdAndHosts[2])
		if erro != nil {
			return redisInfo, zauth.ErrorInputParam
		}
		redisInfo.Port = p
	}

	// secret@localhost
	psdAndHost := strings.Split(psdAndHosts[1], "@")
	if len(psdAndHost) != 2 {
		return redisInfo, zauth.ErrorInputParam
	}

	redisInfo.Psswd = psdAndHost[0]
	redisInfo.Host = psdAndHost[1]
	if redisInfo.Host == "" {
		redisInfo.Host = "locahost"
	}

	redisInfo.Proto = "tcp"
	return redisInfo, nil
}

// Open and init the redis conn pool
func (r *Redis) Open(rd ...interface{}) error {
	if len(rd) != 1 {
		return zauth.ErrorInputParam
	}

	redisInfoStr, ok := rd[0].(string)
	if !ok {
		return zauth.ErrorInputParam
	}

	redisInfo, erro := r.parseUrl(redisInfoStr)
	if erro != nil {
		return zauth.ErrorInputParam
	}

	return r.initPool(&redisInfo)
}

// Set the key:value pair with a expire time
func (r *Redis) Set(key interface{}, value interface{}, tm time.Duration) error {
	conn := r.pool.Get()
	defer conn.Close()

	tms := int64(tm.Seconds())

	_, erro := conn.Do("SETEX", key, tms, value)
	if erro != nil {
		return erro
	}

	return nil
}

// Get a key from the redis
func (r *Redis) Get(key interface{}) (interface{}, error) {
	conn := r.pool.Get()
	defer conn.Close()

	value, erro := conn.Do("GET", key)
	return value, erro
}

// Delete the key
func (r *Redis) Delete(key interface{}) error {
	conn := r.pool.Get()
	defer conn.Close()

	_, erro := conn.Do("DEL", key)
	return erro
}
