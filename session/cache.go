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

// Open ...
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

// New ...
func New(td time.Duration) *Cache {
	c := &Cache{
		items: make(map[interface{}]item, 1000),
		stop:  make(chan struct{}),
	}

	go c.dispatch(td)
	return c
}

// Set ...
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

// Get ...
func (c *Cache) Get(k interface{}) (interface{}, error) {
	c.mut.RLock()
	defer c.mut.RUnlock()

	var i item
	if _, ok := c.items[k]; !ok {
		return nil, zauth.ErrorItemNotFound
	}

	i = c.items[k]
	fmt.Printf("%s\n%s ", time.Now().Format("2006-01-02 15:04:05"), i.expireAt.Format("2006-01-02 15:04:05"))
	if time.Now().After(i.expireAt) {
		return nil, zauth.ErrorItemExpired
	}

	return i.data, nil
}

// Delete ...
func (c *Cache) Delete(k interface{}) error {
	c.mut.Lock()
	delete(c.items, k)
	c.mut.Unlock()

	return nil
}

// Clear ...
func (c *Cache) Clear() error {
	close(c.stop)

	c.mut.Lock()
	c.items = make(map[interface{}]item)
	c.mut.Unlock()
	return nil
}

// Keys ...
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

// Values ...
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

// DelExpiredItem ...
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

// func (d *Deleter)Init(,td time.Duration) {
// 	d.tk := time.NewTicker(td)
// 	go d.dispatch()
// 	return
// }

// func (d *Deleter)start(td time.Duration) {
// 	d.tk := time.NewTicker(td)
// 	go d.dispatch()
// 	return
// }

// func (d *Deleter) clear() {

// }
