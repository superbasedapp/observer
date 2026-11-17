//go:build !sbo_omit_security

package dashboard

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/scrub"
	"github.com/marmutapp/superbased-observer/internal/secassess"
	"github.com/marmutapp/superbased-observer/internal/secassesssvc"
)

// security_assess_display.go is what the model and report routes show of an
// agent's words: the redactor in force (the default patterns plus the
// developer's own [observer.secrets] extra_patterns, like every other seam that
// scrubs), the display copy of a checked model, and the answer's computed parts.
//
// The display copy of a large model is the one costly thing here: redacting
// every string of a 4 MiB model took seconds on the host measured (review of
// 2026-11-14), and the model view reads it again for every comparison. So the
// redacted result is kept in memory per stored copy and redactor, bounded
// (displayCacheEntries entries, displayCacheBudget in all), and the reading, the
// coverage line and the diagram, which cost nothing next to it, are computed
// from it on every request. A cached copy is the value the uncached path
// returns, byte for byte: the key holds everything the copy depends on.

// securityAssessRedactorOf is the redactor a report or model is shown through,
// nil when setting display_redaction is off, and its identity (empty when off):
// two redactors with the same identity redact the same way.
func securityAssessRedactorOf(cfg config.Config) (func(string) string, string) {
	if !cfg.Security.Assessments.DisplayRedaction {
		return nil, ""
	}
	return scrub.NewWithExtra(cfg.Observer.Secrets.ExtraPatterns).String, redactorIdentity(cfg.Observer.Secrets.ExtraPatterns)
}

// redactorIdentity names a redactor by its extra patterns (the default ones
// are compiled in, so a different binary is a different process and an empty
// cache).
func redactorIdentity(extra []string) string {
	h := sha256.New()
	for _, p := range extra {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return "on:" + strconv.Itoa(len(extra)) + ":" + hex.EncodeToString(h.Sum(nil)[:8])
}

// The display cache's bounds. The size of an entry is estimated from the size
// of the agent's file (the decoded model is several times larger than its
// text); an entry over the budget by itself is never kept.
const (
	displayCacheEntries = 4
	displayCacheBudget  = 256 << 20
	displaySizeFactor   = 8
)

// displayKey is everything a display copy depends on.
type displayKey struct {
	side      string // the node's side data (database path): runs of two nodes never meet
	run       string
	validated int64  // the stored copy's ValidatedAt, Unix nanoseconds
	source    string // the validated file's hash
	redactor  string
}

type displayEntry struct {
	key    displayKey
	res    secassess.Result
	hidden int
	size   int64
	used   time.Time
}

// displayCache is a small least-recently-used cache of display copies.
type displayCache struct {
	mu      sync.Mutex
	entries []displayEntry
}

// sharedDisplayCache is the process's cache of display copies.
var sharedDisplayCache displayCache

// get returns the display copy for key, building it with build on a miss. size
// is the estimated size of the copy in bytes.
func (c *displayCache) get(key displayKey, size int64, build func() (secassess.Result, int)) (secassess.Result, int) {
	c.mu.Lock()
	for i := range c.entries {
		if c.entries[i].key == key {
			c.entries[i].used = time.Now()
			e := c.entries[i]
			c.mu.Unlock()
			return e.res, e.hidden
		}
	}
	c.mu.Unlock()

	res, hidden := build()
	if size > displayCacheBudget {
		return res, hidden
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.entries {
		if c.entries[i].key == key { // built by a request that finished first
			return res, hidden
		}
	}
	c.entries = append(c.entries, displayEntry{key: key, res: res, hidden: hidden, size: size, used: time.Now()})
	c.trim()
	return res, hidden
}

// trim drops the least recently used entries until the cache is within both
// bounds. The caller holds the lock.
func (c *displayCache) trim() {
	for {
		var total int64
		oldest := 0
		for i, e := range c.entries {
			total += e.size
			if e.used.Before(c.entries[oldest].used) {
				oldest = i
			}
		}
		if len(c.entries) <= displayCacheEntries && total <= displayCacheBudget {
			return
		}
		c.entries = append(c.entries[:oldest], c.entries[oldest+1:]...)
	}
}

// len reports how many copies are held (tests).
func (c *displayCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// displayResult is the checked model's result as it is shown: redacted when the
// setting is on (cached), as stored when it is off. hidden is how many strings
// of the result the redactor changed.
func (s *Server) displayResult(rec secassesssvc.ModelRecord, redact func(string) string, identity string) (secassess.Result, int) {
	if redact == nil {
		return rec.Result, 0
	}
	key := displayKey{
		side: s.opts.DBPath, run: rec.RunID, validated: rec.ValidatedAt.UnixNano(), source: rec.SourceSHA, redactor: identity,
	}
	return sharedDisplayCache.get(key, rec.SourceBytes*displaySizeFactor, func() (secassess.Result, int) {
		return secassess.RedactResult(rec.Result, redact)
	})
}

// finish fills the parts of the answer that are computed from the stored copy.
// res is the display copy (redacted when hiding is on); redact is nil when it
// is off. The reading and the coverage line are Observer's own sentences built
// from counts, and the diagram's ids are positions in the model, so none of
// them depends on a redacted string being a key: the keys (ids, references,
// paths) are not rewritten by the display pass at all (secassess.redactKeep).
// hidden counts places in this answer: the strings of the model that were
// changed, and those of the comparisons (the stored one and the one asked for),
// so a title shown in both is two places;
// the report route counts the markers it put in the text.
func (m *securityAssessModelJS) finish(res secassess.Result, hidden int, redact func(string) string, a config.SecurityAssessmentsConfig) {
	m.Record.Result = res
	if m.Since != nil {
		d, n := secassess.RedactValue(*m.Since, redact)
		m.Since, hidden = &d, hidden+n
	}
	// The comparison a checked threat model carries in its stored copy (the
	// earlier run it was started to be compared with) holds the agent's titles
	// and names too: it passes the same redactor as the model beside it.
	if m.Record.Diff != nil {
		d, n := secassess.RedactValue(*m.Record.Diff, redact)
		m.Record.Diff, hidden = &d, hidden+n
	}
	m.Reading = secassess.CleanReading(res)
	m.CoverageLine = secassess.CoverageLine(res)
	if tm := res.TM; tm != nil {
		d := secassess.RenderMermaidWith(tm, secassess.MermaidOptions{MaxNodes: a.DiagramMaxNodes, LabelChars: a.DiagramLabelChars})
		m.Mermaid = &d
	}
	m.Redaction = securityAssessRedactionJS{On: redact != nil, Hidden: hidden}
}
