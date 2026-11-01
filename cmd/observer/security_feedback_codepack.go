//go:build !sbo_omit_security && !sbo_omit_security_scan_opengrep

package main

import (
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/secrulepack"
)

// security_feedback_codepack.go is the code rule pack's row of the feedback
// rule table (lane SEC-H2, audit finding F5): a finding of pack
// observer-code names its rule in a feedback line only when the id is a
// rule of the pack in use, the embedded floor or a newer pack that
// re-verified through the signed content channel (loadCodePack). An id the
// pack does not hold, or any id while no pack loads, is not named (the
// line names the category). Built only with the Opengrep driver.

// feedbackCodePackTTL bounds how long a loaded pack's rule set is reused
// before the pack is loaded again (an imported pack may replace it).
const feedbackCodePackTTL = time.Minute

// feedbackCodePackState is the one owner of the cached rule set. The pack
// is loaded and refreshed in the background (SEC-H2 merge, audit finding
// 5): binding the config path starts the first load, and a stale set
// starts a refresh while answers keep using the set they have, so a
// feedback answer never loads the pack inside its 50 ms budget. Until the
// first load lands no id is named (the line names the category).
type feedbackCodePackState struct {
	mu       sync.Mutex
	config   string
	gen      int
	loadedAt time.Time
	has      func(id string) bool
	loading  bool
	now      func() time.Time
	// load is the pack load (loadFeedbackCodePack; a test swaps it).
	load func(configPath string) func(string) bool
}

// feedbackCodePack is the process's rule set.
var feedbackCodePack = &feedbackCodePackState{load: loadFeedbackCodePack}

func init() {
	feedbackRuleTables[secrulepack.PackID] = feedbackCodePackRule
	feedbackConfigBinders = append(feedbackConfigBinders, feedbackCodePack.bind)
}

// bind sets the config path the pack is read for and starts its load; the
// same path again keeps the set already loaded or loading.
func (c *feedbackCodePackState) bind(configPath string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.config == configPath && (c.has != nil || c.loading) {
		return
	}
	c.config, c.has = configPath, nil
	c.gen++
	c.refreshLocked()
}

// clock is the state's clock.
func (c *feedbackCodePackState) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

// refreshLocked starts one background load unless one runs (c.mu held). A
// load for a config path rebound while it ran is discarded and a new one
// starts.
func (c *feedbackCodePackState) refreshLocked() {
	if c.loading {
		return
	}
	c.loading = true
	cfg, gen, load := c.config, c.gen, c.load
	go func() {
		has := load(cfg)
		c.mu.Lock()
		defer c.mu.Unlock()
		c.loading = false
		if c.gen != gen {
			c.refreshLocked()
			return
		}
		c.has, c.loadedAt = has, c.clock()
	}()
}

// rule reports whether id is a rule of the loaded pack. It never loads the
// pack itself: a missing or stale set only starts a background load.
func (c *feedbackCodePackState) rule(id string) bool {
	c.mu.Lock()
	if c.has == nil || c.clock().Sub(c.loadedAt) > feedbackCodePackTTL {
		c.refreshLocked()
	}
	has := c.has
	c.mu.Unlock()
	return has != nil && has(id)
}

// feedbackCodePackRule knows the rule ids of the verified pack in use.
func feedbackCodePackRule(id string) bool { return feedbackCodePack.rule(id) }

// loadFeedbackCodePack loads the pack in use for configPath and returns its
// rule lookup; a pack that cannot load knows no id.
func loadFeedbackCodePack(configPath string) func(string) bool {
	none := func(string) bool { return false }
	resolved, err := config.ResolveGlobalPath(configPath)
	if err != nil {
		return none
	}
	cp, err := loadCodePack(codeRulesStore(resolved), codeRulesTrust())
	if err != nil || cp.Pack == nil {
		return none
	}
	pack := cp.Pack
	return func(id string) bool {
		_, ok := pack.Rule(id)
		return ok
	}
}
