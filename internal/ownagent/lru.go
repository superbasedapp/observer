package ownagent

import "container/list"

// lru is a fixed-capacity least-recently-used map. Get and Put both count as
// a use; Put evicts the least recently used key when the map is full, so an
// active key is never dropped in favour of a stale one. Not safe for
// concurrent use: the Tracker's mutex guards it.
type lru[V any] struct {
	cap   int
	order *list.List // front = most recently used; values are *lruEntry[V]
	items map[string]*list.Element
}

type lruEntry[V any] struct {
	key string
	val V
}

func newLRU[V any](capacity int) *lru[V] {
	if capacity < 1 {
		capacity = 1
	}
	return &lru[V]{cap: capacity, order: list.New(), items: map[string]*list.Element{}}
}

// Get returns the value for key and marks it used.
func (c *lru[V]) Get(key string) (V, bool) {
	el, ok := c.items[key]
	if !ok {
		var zero V
		return zero, false
	}
	c.order.MoveToFront(el)
	return el.Value.(*lruEntry[V]).val, true
}

// Put stores val under key, marks it used and evicts the least recently
// used entry when the map is over capacity.
func (c *lru[V]) Put(key string, val V) {
	if el, ok := c.items[key]; ok {
		el.Value.(*lruEntry[V]).val = val
		c.order.MoveToFront(el)
		return
	}
	c.items[key] = c.order.PushFront(&lruEntry[V]{key: key, val: val})
	for c.order.Len() > c.cap {
		old := c.order.Back()
		c.order.Remove(old)
		delete(c.items, old.Value.(*lruEntry[V]).key)
	}
}

// Len reports the number of entries.
func (c *lru[V]) Len() int { return c.order.Len() }
