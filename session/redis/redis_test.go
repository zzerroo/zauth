package redis

import (
	"fmt"
	"testing"
	"time"

	"github.com/zzerroo/zauth/util"
)

func getRedis() (*Redis, error) {
	return NewRedis(&RedisInfo{"tcp", "127.0.0.1", 6379, "xxxx", -1, 10, 10, 10})
}

func TestRedisOpen(t *testing.T) {
	r, erro := getRedis()
	if erro != nil {
		t.Errorf("error create a new redis,info " + erro.Error())
	}

	key := "foo"
	value := "bar"

	erro = r.Set(key, value, 10*time.Second)
	if erro != nil {
		t.Errorf("error set data,info: " + erro.Error())
	}

	v, erro := r.Get(key)
	if erro != nil {
		t.Errorf("error set data,info: " + erro.Error())
	}

	v2 := util.Byte2String(v.([]byte))

	if v2 != value {
		t.Errorf("error data,data: " + v2)
	}

	t.Log("ok")
}

func TestRedisGet(t *testing.T) {
	r, erro := getRedis()
	if erro != nil {
		t.Errorf("error create a new redis,info " + erro.Error())
	}

	k := "foo"
	v := "bar"

	erro = r.Set(k, v, 5*time.Second)
	if erro != nil {
		t.Errorf("error set data, error: " + erro.Error())
	}

	// get a data exist
	v2, erro := r.Get(k)
	if erro != nil {
		t.Errorf("error get data, error: " + erro.Error())
	}

	s := util.Byte2String(v2.([]byte))
	if s != v {
		t.Errorf("error get data, data: " + erro.Error())
	}

	// get a data not exist
	v2, erro = r.Get(k + "tmp")
	if erro != nil {
		t.Errorf("error get data, error: " + erro.Error())
	}

	if v2 != nil {
		t.Errorf("error get data, error: v2 should be nil")
	}

	time.Sleep(5 * time.Second)

	// get a data expire
	v2, erro = r.Get(k)
	if erro != nil || v2 != nil {
		t.Errorf("error get data, error shuold be nil and v4 should be nil")
	}

	// reset the data
	erro = r.Set(k, v, 5*time.Second)
	if erro != nil {
		t.Errorf("error set data, error: " + erro.Error())
	}

	erro = r.Delete(k)
	if erro != nil {
		t.Errorf("error del data,error: " + erro.Error())
	}

	// get a delete data
	v2, erro = r.Get(k)
	if erro != nil || v2 != nil {
		t.Errorf("error get data, error shuold be nil and v4 should be nil")
	}

	t.Logf("ok" + fmt.Sprintf("%T", v2))
}

func TestRedisSet(t *testing.T) {
	r, erro := getRedis()
	if erro != nil {
		t.Errorf("error create a new redis,info " + erro.Error())
	}

	k1 := "foo"
	v1 := "bar"
	k2 := "foo2"
	v2 := 2

	// string
	erro = r.Set(k1, v1, 5*time.Second)
	if erro != nil {
		t.Errorf("error set data, error: " + erro.Error())
	}

	v, erro := r.Get(k1)
	if erro != nil {
		t.Errorf("error get data, error: " + erro.Error())
	}

	vStr := util.Byte2String(v.([]byte))
	if v1 != vStr {
		t.Errorf("error get data, error: v1 != vStr")
	}

	// reset the data
	erro = r.Set(k2, v2, 5*time.Second)
	if erro != nil {
		t.Errorf("error set data, error: " + erro.Error())
	}

	v22, erro := r.Get(k2)
	if erro != nil {
		t.Errorf("error get data, error: " + erro.Error())
	}

	vStr22 := util.Byte2String(v22.([]byte))
	if fmt.Sprintf("%d", v2) != vStr22 {
		t.Errorf("error get data, error: v1 != vStr")
	}

	t.Log("ok")
}

func TestRedisParse(t *testing.T) {
	r, erro := getRedis()
	if erro != nil {
		t.Errorf("error create a redis, error: " + erro.Error())
	}

	url := "redis://user:xxxx@127.0.0.1:6379/0?active=10&idle=5&itimeout=2"

	redisInfo, erro := r.parseUrl(url)
	if erro != nil {
		t.Errorf("error parse a url, error: " + erro.Error())
	}

	if redisInfo.DB != 0 ||
		redisInfo.Psswd != "secret" ||
		redisInfo.Host != "127.0.0.1" ||
		redisInfo.Port != 6379 ||
		redisInfo.MaxActive != 10 ||
		redisInfo.MacxIdle != 5 ||
		redisInfo.IdelTimeout != 2 {
		t.Errorf("error parse a url")
	}

	// test default
	url = "redis://user:secretxxx@:/?active=21&idle=15&itimeout=2"
	redisInfo, erro = r.parseUrl(url)
	if erro != nil {
		t.Errorf("error parse a url, error: " + erro.Error())
	}

	if redisInfo.DB != 0 ||
		redisInfo.Psswd != "secretxxx" ||
		redisInfo.Host != "localhost" ||
		redisInfo.Port != 6379 ||
		redisInfo.MaxActive != 21 ||
		redisInfo.MacxIdle != 15 ||
		redisInfo.IdelTimeout != 2 {
		t.Errorf("error parse a url")
	}

	t.Log("ok")
}
