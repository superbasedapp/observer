package main

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// policystate_liveswitch.go makes the policy-state reporter's LOCAL opt-in,
// [org_client.share].policy_state, a live read (round 3, 2026-11-11), the way
// round 2 made the policy poller's accept lists live
// (policyresource_livelists.go). The reporter used to copy the value once at
// daemon start, so turning the share on (by hand, from the dashboard's
// Privacy card, or by an enrolment that writes it) left the org's Control
// Center at "No authority report from this node yet" until a restart. The
// node.governance raise/lower half was already live (effectiveEnabled reads
// the handle on every report); this closes the local half.

// liveConfigSwitch is one boolean read from config.toml, re-read when the
// file's stamp changes (a stat per read, a load only on change). A config
// that does not load keeps the last value. path empty is a static switch.
type liveConfigSwitch struct {
	path   string
	get    func(config.Config) bool
	load   func(path string) (config.Config, error)
	logger *slog.Logger

	mu       sync.Mutex
	val      bool
	stamp    policyFileStamp
	loadFail bool
}

// newLiveConfigSwitch starts from the value in cfg (the config the daemon
// loaded) and follows path from then on.
func newLiveConfigSwitch(cfg config.Config, path string, get func(config.Config) bool, logger *slog.Logger) *liveConfigSwitch {
	if logger == nil {
		logger = slog.Default()
	}
	return &liveConfigSwitch{
		path: path, get: get, val: get(cfg), stamp: statStamp(path), logger: logger,
		load: func(p string) (config.Config, error) { return config.Load(config.LoadOptions{GlobalPath: p}) },
	}
}

// value returns the switch's current value, reloading first when the file
// changed.
func (s *liveConfigSwitch) value() bool {
	if s == nil {
		return false
	}
	s.refresh()
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.val
}

// refresh reloads the value when the file changed and reports whether the
// value itself changed.
func (s *liveConfigSwitch) refresh() bool {
	if s == nil || s.path == "" {
		return false
	}
	st := statStamp(s.path)
	s.mu.Lock()
	defer s.mu.Unlock()
	if !st.ok || st == s.stamp {
		return false
	}
	next, err := s.load(s.path)
	if err != nil {
		if !s.loadFail {
			s.logger.Warn("config.toml did not load; keeping the setting in force", "err", err)
		}
		s.loadFail = true
		return false
	}
	s.loadFail = false
	s.stamp = st
	v := s.get(next)
	if v == s.val {
		return false
	}
	s.val = v
	return true
}

// watchLiveConfigSwitch calls poke whenever the switch's value changes, until
// ctx ends.
func watchLiveConfigSwitch(ctx context.Context, sw *liveConfigSwitch, poke func(), interval time.Duration) {
	if sw == nil || sw.path == "" || poke == nil {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if sw.refresh() {
			poke()
		}
	}
}
