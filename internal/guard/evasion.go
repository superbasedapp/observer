package guard

import (
	"sync"
	"time"
)

// evasionTracker is the A-613 policy-evasion tracker (D-761, security
// pillar plan section 5.2): per session and per rule, the differently
// shaped actions that rule denied or asked about within the window. It
// lives in the daemon and feeds Event.EvasionOf / Event.EvasionShapes on
// the watcher ingest path only (a hook process is too short-lived to
// remember anything), like the A-610 repeat tracker. Bounded: at most
// maxEvasionSessions sessions and maxEvasionShapes shapes per rule;
// overflow forgets, which can only miss a flag, never invent one.
type evasionTracker struct {
	mu       sync.Mutex
	sessions map[string]map[string][]evasionShape
}

// evasionShape is one refused action shape and when it was seen.
type evasionShape struct {
	key string
	at  time.Time
}

const (
	maxEvasionSessions = 256
	maxEvasionShapes   = 32
)

// Observe records that ruleID refused an action of shape key at now and
// returns how many OTHER shapes it refused in this session within window
// before it. A window of zero turns the tracker off (returns 0, records
// nothing).
func (t *evasionTracker) Observe(sessionID, ruleID, key string, now time.Time, window time.Duration) int {
	if window <= 0 || sessionID == "" || ruleID == "" {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.sessions == nil {
		t.sessions = map[string]map[string][]evasionShape{}
	}
	rules := t.sessions[sessionID]
	if rules == nil {
		if len(t.sessions) >= maxEvasionSessions {
			for k := range t.sessions {
				delete(t.sessions, k)
				break
			}
		}
		rules = map[string][]evasionShape{}
		t.sessions[sessionID] = rules
	}
	kept := rules[ruleID][:0]
	others := 0
	for _, s := range rules[ruleID] {
		if now.Sub(s.at) > window || s.key == key {
			continue
		}
		kept = append(kept, s)
		others++
	}
	kept = append(kept, evasionShape{key: key, at: now})
	if len(kept) > maxEvasionShapes {
		kept = kept[len(kept)-maxEvasionShapes:]
	}
	rules[ruleID] = kept
	return others
}
