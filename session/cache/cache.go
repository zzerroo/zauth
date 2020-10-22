package session

import (
	"fmt"
	"sync"
	"time"

	"github.com/zzerroo/zauth"
)

// Cache ...
type Cache struct {
	items map[interface{}]item
	mut   sync.RWMutex
	tk    *time.Ticker
	stop  chan struct{}
}

type item struct {
	data     interface{}
	expireAt time.Time
}

// DefaultTD ...
const DefaultTD = 1 * time.Second

func init() {
	zauth.RegisterSession(zauth.CacheSession, &Cache{})
}

// Init ...
func (c *Cache) Init() {
	return
}

// Open the cache
func (c *Cache) Open(td ...interface{}) error {
	c.items = make(map[interface{}]item, 1000)
	c.stop = make(chan struct{})

	if td, ok := td[0].(time.Duration); ok {
		go c.dispatch(td)
		return nil
	}

	go c.dispatch(DefaultTD)
	return nil
}

// New create a new Cache{}
func New(td time.Duration) *Cache {
	c := &Cache{
		items: make(map[interface{}]item, 1000),
		stop:  make(chan struct{}),
	}

	go c.dispatch(td)
	return c
}

// Set the k:d to the cache, with a du expiration time
func (c *Cache) Set(k interface{}, d interface{}, du time.Duration) error {
	tm := time.Now()
	fmt.Printf("%s\n%s\n", tm.Format("2006-01-02 15:04:05"), tm.Add(du).Format("2006-01-02 15:04:05"))
	c.mut.Lock()
	c.items[k] = item{
		data:     d,
		expireAt: time.Now().Add(du),
	}
	c.mut.Unlock()
	return nil
}

// Get the value with k
// Return Value:
//	ErrorItemNotFound item not found in the cache
//	ErrorItemExpired has expired
//	nil success
func (c *Cache) Get(k interface{}) (interface{}, error) {
	c.mut.RLock()
	defer c.mut.RUnlock()

	var i item
	if _, ok := c.items[k]; !ok {
		return nil, zauth.ErrorItemNotFound
	}

	i = c.items[k]
	if time.Now().After(i.expireAt) {
		return nil, zauth.ErrorItemExpired
	}

	return i.data, nil
}

// Delete the pair with the key k
func (c *Cache) Delete(k interface{}) error {
	c.mut.Lock()
	delete(c.items, k)
	c.mut.Unlock()

	return nil
}

// Clear delete all pairs
func (c *Cache) Clear() error {
	close(c.stop)

	c.mut.Lock()
	c.items = make(map[interface{}]item)
	c.mut.Unlock()
	return nil
}

// Keys get all keys from the cache
func (c *Cache) Keys() ([]interface{}, error) {
	c.mut.RLock()
	tm := time.Now()
	keys := make([]interface{}, 0, 0)

	for k, v := range c.items {
		if tm.Before(v.expireAt) {
			keys = append(keys, k)
		}
	}
	c.mut.RUnlock()
	return keys, nil
}

// Values get all values
func (c *Cache) Values() ([]interface{}, error) {
	c.mut.RLock()
	values := make([]interface{}, 0, 0)
	tm := time.Now()
	for _, v := range c.items {
		if tm.Before(v.expireAt) {
			values = append(values, v.data)
		}
	}
	c.mut.RUnlock()
	return values, nil
}

// DelExpiredItem del the expired item
func (c *Cache) delExpiredItem() {
	c.mut.Lock()
	now := time.Now()
	for k, v := range c.items {
		if now.After(v.expireAt) {
			delete(c.items, k)
		}
	}
	c.mut.Unlock()
}

// start a ticker for del the expired item
func (c *Cache) dispatch(td time.Duration) {
	c.tk = time.NewTicker(td)
	select {
	case <-c.stop:
		{
			break
		}
	case <-c.tk.C:
		{
			c.delExpiredItem()
		}
	default:
		{
		}
	}
}
