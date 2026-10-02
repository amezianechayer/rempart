package envelope

import (
	"container/list"
	"crypto/cipher"
	"time"

	"github.com/amezianechayer/rempart/internal/tenancy"
)

// cacheKey includes the tenant (T23).
type cacheKey struct {
	tenant tenancy.ID
	id     [16]byte
}

type cacheEntry struct {
	key     cacheKey
	aead    cipher.AEAD
	created time.Time
	uses    uint64
}

// aeadCache is a bounded LRU of AEADs, never of raw DEKs (D3). Not safe for
// concurrent use: the Sealer holds its lock.
type aeadCache struct {
	max     int
	maxAge  time.Duration
	maxUses uint64
	order   *list.List
	byKey   map[cacheKey]*list.Element
}

func newAEADCache(maxEntries int, maxAge time.Duration, maxUses uint64) *aeadCache {
	return &aeadCache{max: maxEntries, maxAge: maxAge, maxUses: maxUses, order: list.New(), byKey: map[cacheKey]*list.Element{}}
}

// get returns a live entry and counts one use, or nil.
func (c *aeadCache) get(k cacheKey, now time.Time) cipher.AEAD {
	el, ok := c.byKey[k]
	if !ok {
		return nil
	}
	e, ok := el.Value.(*cacheEntry)
	if !ok || now.Sub(e.created) >= c.maxAge || e.uses >= c.maxUses {
		c.order.Remove(el)
		delete(c.byKey, k)
		return nil
	}
	e.uses++
	c.order.MoveToFront(el)
	return e.aead
}

// put inserts or replaces an entry, evicting the least recently used ones.
func (c *aeadCache) put(k cacheKey, a cipher.AEAD, now time.Time, uses uint64) {
	if el, ok := c.byKey[k]; ok {
		c.order.Remove(el)
		delete(c.byKey, k)
	}
	c.byKey[k] = c.order.PushFront(&cacheEntry{key: k, aead: a, created: now, uses: uses})
	for c.order.Len() > c.max {
		back := c.order.Back()
		c.order.Remove(back)
		if e, ok := back.Value.(*cacheEntry); ok {
			delete(c.byKey, e.key)
		}
	}
}
