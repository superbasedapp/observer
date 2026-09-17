package main

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/remoteauth"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// openPersistTestDB opens the daemon DB the CLI verbs write, for the test to
// build a persister-backed SessionStore over the SAME file.
func openPersistTestDB(t *testing.T, cfgPath string) (config.Config, *sql.DB) {
	t.Helper()
	cfg, err := config.Load(config.LoadOptions{GlobalPath: cfgPath})
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	database, err := dbtemplate.Open(context.Background(), db.Options{Path: cfg.Observer.DBPath})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return cfg, database
}

func newPersistStore(database *sql.DB) *remoteauth.SessionStore {
	return remoteauth.NewSessionStore(remoteauth.SessionParams{
		TTL:       12 * time.Hour,
		Idle:      time.Hour,
		Max:       5,
		Persister: store.NewRemoteSessionPersister(database),
	})
}

// TestRemoteRotateInvalidatesPersistedSessionsAcrossRestart exercises the CLI
// durable fence end-to-end: a device paired after `enable` is refused after a
// `rotate` + restart.
func TestRemoteRotateInvalidatesPersistedSessionsAcrossRestart(t *testing.T) {
	cfgPath, _ := writeRemoteTestConfig(t)
	if _, err := runRemote(t, "enable", "--tailscale", "--host", "box.ts.net", "--config", cfgPath); err != nil {
		t.Fatalf("enable: %v", err)
	}

	// A device pairs (session persisted at the current generation).
	_, database := openPersistTestDB(t, cfgPath)
	s1 := newPersistStore(database)
	raw, err := s1.Create()
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	if err := s1.Validate(raw); err != nil {
		t.Fatalf("validate pre-rotate: %v", err)
	}

	// Operator rotates (separate process → advances the durable fence).
	if _, err := runRemote(t, "rotate", "--config", cfgPath); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	// Restart: a fresh store over the same DB must refuse the old cookie.
	s2 := newPersistStore(database)
	if err := s2.Validate(raw); err == nil {
		t.Fatal("rotated device cookie must be refused after restart")
	}
}

// TestRemoteDisableInvalidatesPersistedSessionsAcrossRestart: disable advances
// the SAME fence as rotate, so a paired device is refused after restart.
func TestRemoteDisableInvalidatesPersistedSessionsAcrossRestart(t *testing.T) {
	cfgPath, _ := writeRemoteTestConfig(t)
	if _, err := runRemote(t, "enable", "--tailscale", "--host", "box.ts.net", "--config", cfgPath); err != nil {
		t.Fatalf("enable: %v", err)
	}
	_, database := openPersistTestDB(t, cfgPath)
	s1 := newPersistStore(database)
	raw, _ := s1.Create()
	if err := s1.Validate(raw); err != nil {
		t.Fatalf("validate pre-disable: %v", err)
	}

	if _, err := runRemote(t, "disable", "--config", cfgPath); err != nil {
		t.Fatalf("disable: %v", err)
	}

	s2 := newPersistStore(database)
	if err := s2.Validate(raw); err == nil {
		t.Fatal("device cookie must be refused after disable + restart")
	}
}
