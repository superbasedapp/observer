package secfeed

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
)

// cache.go is the online-answer cache's rules and its hook-readable file
// (security plan section 8.3 "Cache"): positive facts 24 hours, answers
// carrying advisories 6 hours, "not found" 1 hour (an attacker can register
// the name later), failures 2 minutes. The daemon owns the cache (the
// node-local sec_pkg_cache table through its store seam, and this file);
// the hook only reads the file. A failed lookup is cached briefly (lane
// sec-d1fix): the same name installed again within minutes reads the same
// failure at once instead of waiting out the install-gate budget again.

// The cache lifetimes.
const (
	CacheTTLPositive = 24 * time.Hour
	CacheTTLAdvisory = 6 * time.Hour
	CacheTTLNotFound = time.Hour
	CacheTTLFailed   = 2 * time.Minute
)

// uncachedFailures are failure reasons that say nothing about the
// package: the tenancy could not be read, or nobody answered this ask.
var uncachedFailures = map[string]bool{
	ReasonTenancyUnknown: true, GateReasonNoAnswer: true, GateReasonAskFailed: true, ReasonInFlight: true,
}

// ReasonTenancyUnknown and ReasonInFlight are failure reasons the daemon
// side writes: the node's tenancy could not be read (no lookup ran), or a
// lookup is still running when the ask's budget ended (its answer is
// cached when it lands).
const (
	ReasonTenancyUnknown = "tenancy_unknown"
	ReasonInFlight       = "in_flight"
)

// Caps on the cache file the hook reads.
const (
	MaxCacheFileBytes   = 8 << 20
	MaxCacheFileEntries = 20000
	cacheFileVersion    = 1
)

// CacheTTL returns how long an answer may be served from the cache; 0
// means it is never cached.
func CacheTTL(a OnlineAnswer) time.Duration {
	switch a.Status {
	case OnlineNotFound:
		return CacheTTLNotFound
	case OnlineAnswered:
		if len(a.MalIDs) > 0 || len(a.VulnIDs) > 0 {
			return CacheTTLAdvisory
		}
		return CacheTTLPositive
	case OnlineFailed:
		if a.Reason == "" || uncachedFailures[a.Reason] {
			return 0
		}
		return CacheTTLFailed
	}
	return 0
}

// CacheEntry is one cached answer.
type CacheEntry struct {
	Answer    OnlineAnswer `json:"answer"`
	ExpiresAt time.Time    `json:"expires_at"`
}

// NewCacheEntry stamps an answer with its expiry; ok is false for an
// answer that is never cached.
func NewCacheEntry(a OnlineAnswer, now time.Time) (CacheEntry, bool) {
	ttl := CacheTTL(a)
	if ttl == 0 {
		return CacheEntry{}, false
	}
	a.Name = Normalize(a.Eco, a.Name)
	if a.FetchedAt.IsZero() {
		a.FetchedAt = now
	}
	return CacheEntry{Answer: a, ExpiresAt: now.Add(ttl)}, true
}

// cacheFile is the file's shape.
type cacheFile struct {
	V         int          `json:"v"`
	WrittenAt time.Time    `json:"written_at"`
	Entries   []CacheEntry `json:"entries"`
}

// EncodeCacheFile writes the live entries, newest first, capped.
func EncodeCacheFile(entries []CacheEntry, now time.Time) ([]byte, error) {
	live := make([]CacheEntry, 0, len(entries))
	for _, e := range entries {
		if now.Before(e.ExpiresAt) {
			live = append(live, e)
		}
	}
	sort.Slice(live, func(i, j int) bool { return live[i].Answer.FetchedAt.After(live[j].Answer.FetchedAt) })
	if len(live) > MaxCacheFileEntries {
		live = live[:MaxCacheFileEntries]
	}
	b, err := json.Marshal(cacheFile{V: cacheFileVersion, WrittenAt: now.UTC(), Entries: live})
	if err != nil {
		return nil, fmt.Errorf("secfeed.EncodeCacheFile: %w", err)
	}
	return b, nil
}

// Cache is a decoded cache.
type Cache struct {
	entries map[string]CacheEntry
	now     time.Time
}

// ErrCacheFile wraps a refused cache file; the hook then has no cache.
var ErrCacheFile = errors.New("secfeed: cache file refused")

// DecodeCacheFile reads the cache file strictly; entries past their expiry
// are dropped at read.
func DecodeCacheFile(b []byte, now time.Time) (*Cache, error) {
	if len(b) > MaxCacheFileBytes {
		return nil, fmt.Errorf("%w: %d bytes", ErrCacheFile, len(b))
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var f cacheFile
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCacheFile, err)
	}
	if f.V != cacheFileVersion || len(f.Entries) > MaxCacheFileEntries {
		return nil, fmt.Errorf("%w: version %d, %d entries", ErrCacheFile, f.V, len(f.Entries))
	}
	c := &Cache{entries: make(map[string]CacheEntry, len(f.Entries)), now: now}
	for _, e := range f.Entries {
		if !now.Before(e.ExpiresAt) || CacheTTL(e.Answer) == 0 {
			continue
		}
		c.entries[answerKey(e.Answer.Eco, e.Answer.Name, e.Answer.Version)] = e
	}
	return c, nil
}

// NewCache builds an in-memory cache from entries (the daemon's view).
func NewCache(entries []CacheEntry, now time.Time) *Cache {
	c := &Cache{entries: make(map[string]CacheEntry, len(entries)), now: now}
	for _, e := range entries {
		if now.Before(e.ExpiresAt) {
			c.entries[answerKey(e.Answer.Eco, e.Answer.Name, e.Answer.Version)] = e
		}
	}
	return c
}

// Lookup is the gate's CacheLookup over c; a nil cache answers nothing.
func (c *Cache) Lookup(eco Ecosystem, name, version string) (OnlineAnswer, bool) {
	if c == nil {
		return OnlineAnswer{}, false
	}
	e, ok := c.entries[answerKey(eco, name, version)]
	if !ok || !c.now.Before(e.ExpiresAt) {
		return OnlineAnswer{}, false
	}
	return e.Answer, true
}

// Len reports the live entries.
func (c *Cache) Len() int {
	if c == nil {
		return 0
	}
	return len(c.entries)
}
