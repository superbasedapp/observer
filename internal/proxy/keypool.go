package proxy

import (
	"crypto/subtle"
	"net/http"
	"strings"
	"sync/atomic"
)

// Multi-key rotation (§R12.4): a same-provider key pool rotated on
// rate-limit pressure — LiteLLM key-pool parity for the single node.
// The pool lives ONLY in the node's local config.toml ([routing.
// key_pool]); it is never synced, never pushed, and key material is
// never logged (rotation logs an index, nothing else). The §R11.5
// keychain-backed vault is the P3 upgrade path.
//
// Membership guard (SR27-B2): a key swaps ONLY into a request that already
// presented one of the pool's own keys - list every key the client may be
// configured with in the pool.
//
// Rotation guard (G7): keys swap ONLY into requests that already
// carried the same credential form — an x-api-key header rotates
// x-api-key; a Bearer sk-* rotates the bearer. OAuth / JWT requests
// (subscription entitlement) are NEVER touched: substituting an API
// key under a subscription request changes billing semantics.

// keyPool is one provider's rotating key ring.
type keyPool struct {
	keys []string
	next atomic.Uint64
}

// buildKeyPools converts the Options map.
func buildKeyPools(cfg map[string][]string) map[string]*keyPool {
	if len(cfg) == 0 {
		return nil
	}
	out := make(map[string]*keyPool, len(cfg))
	for provider, keys := range cfg {
		clean := make([]string, 0, len(keys))
		for _, k := range keys {
			if k != "" {
				clean = append(clean, k)
			}
		}
		if len(clean) > 0 {
			out[provider] = &keyPool{keys: clean}
		}
	}
	return out
}

// rotateAuth applies the pool's next key to the request, honoring the
// credential-form guard. Returns false (request untouched) when the
// request's auth form is not rotatable or no pool exists.
func (p *Proxy) rotateAuth(req *http.Request, provider string) bool {
	pool, ok := p.keyPools[provider]
	if !ok || len(pool.keys) < 2 {
		return false
	}
	switch {
	case req.Header.Get("x-api-key") != "":
		if !pool.contains(req.Header.Get("x-api-key")) {
			return false
		}
		req.Header.Set("x-api-key", pool.nextKey())
		return true
	case strings.HasPrefix(req.Header.Get("Authorization"), "Bearer sk-") &&
		!strings.HasPrefix(req.Header.Get("Authorization"), "Bearer sk-ant-oat"):
		if !pool.contains(strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")) {
			return false
		}
		req.Header.Set("Authorization", "Bearer "+pool.nextKey())
		return true
	default:
		// OAuth / JWT / unauthenticated: never substitute (G7).
		return false
	}
}

// nextKey advances the ring and returns its next key.
func (k *keyPool) nextKey() string {
	return k.keys[k.next.Add(1)%uint64(len(k.keys))]
}

// contains reports, in constant time per key, whether presented is one of the
// pool's own keys. Rotation is a way to spread the OPERATOR's own traffic over
// the operator's keys; a request that arrived with some other credential (a
// caller's own, deliberately rate-limited key) must never be upgraded to an
// operator key on a 429 (security review 2026-09-27, SR27-B2).
func (k *keyPool) contains(presented string) bool {
	found := 0
	for _, key := range k.keys {
		found |= subtle.ConstantTimeCompare([]byte(presented), []byte(key))
	}
	return found == 1
}
