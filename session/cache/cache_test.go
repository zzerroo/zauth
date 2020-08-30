package session

import (
	"strconv"
	"sync"
	"testing"
	"time"
	"github.com/zzerroo/zauth"
)

func TestNew(t *testing.T) {
	cache := New(1 * time.Second)
	if cache == nil {
		t.Errorf("error create cache")
	}

	t.Log("ok")
}

func TestSet(t *testing.T) {
	cache := New(1 * time.Second)
	if cache == nil {
		t.Errorf("error create cache")
	}

	k := "key"
	v := "xxxx"

	erro := cache.Set(k, v, 1*time.Second)
	if erro != nil {
		t.Error("error set data,info: " + erro.Error())
	}

	v2, erro := cache.Get(k)
	if erro != nil {
		t.Error("error get data,info: " + erro.Error())
	}

	if v != v2 {
		t.Error("error data ")
	}

	keys, erro := cache.Keys()
	if erro != nil {
		t.Errorf("error get keys,info: " + erro.Error())
	}

	if len(keys) != 1 || keys[0] != k {
		t.Errorf("error get data")
	}

	values, erro := cache.Values()
	if len(values) != 1 || values[0] != v {
		t.Errorf("error get data")
	}

	time.Sleep(1 * time.Second)

	_, erro = cache.Get(k)
	if erro != zauth.ErrorItemExpired {
		t.Error("error get data,data not expire ")
	}
}

func TestSetM(t *testing.T) {
	cache := New(1 * time.Second)
	if cache == nil {
		t.Errorf("error create cache")
	}

	var wg sync.WaitGroup

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			erro := cache.Set(strconv.Itoa(i), strconv.Itoa(i), 2*time.Second)
			if erro != nil {
				t.Errorf("error set data,info:" + erro.Error())
			}

			_, erro = cache.Get(strconv.Itoa(i))
			if erro != nil {
				t.Errorf("error get data,info:" + erro.Error() + strconv.Itoa(i))
			}

			keys, erro := cache.Keys()
			if erro != nil || len(keys) == 0 {
				t.Errorf("error get keys,info:" + erro.Error() + strconv.Itoa(i))
			}

			values, erro := cache.Keys()
			if erro != nil || len(values) == 0 {
				t.Errorf("error get datas,info:" + erro.Error() + strconv.Itoa(i))
			}

			erro = cache.Delete(strconv.Itoa(i))
			if erro != nil {
				t.Errorf("error delete data,info:" + erro.Error() + strconv.Itoa(i))
			}
		}(i)
	}

	wg.Wait()
}

func TestDelete(t *testing.T) {
	cache := New(1 * time.Second)
	if cache == nil {
		t.Errorf("error create cache")
	}

	k := "key"
	v := "xxxx"

	erro := cache.Set(k, v, 10*time.Second)
	if erro != nil {
		t.Errorf("error set data,info: " + erro.Error())
	}

	v1, erro := cache.Get(k)
	if erro != nil || v != v1 {
		t.Errorf("error get data,info:" + erro.Error())
	}

	erro = cache.Delete(k)
	if erro != nil {
		t.Errorf("error del data,info:" + erro.Error())
	}

	v1, erro = cache.Get(k)
	if erro != zauth.ErrorItemNotFound {
		t.Errorf("error get data,info:" + erro.Error())
	}

	erro = cache.Delete(k)
	if erro != nil {
		t.Errorf("error del data,info:" + erro.Error())
	}
}
