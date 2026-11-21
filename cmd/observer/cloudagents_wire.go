package main

import (
	"context"
	"database/sql"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/marmutapp/superbased-observer/internal/cloudagentsnet"
	"github.com/marmutapp/superbased-observer/internal/cloudagentssvc"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/keystore"
	"github.com/marmutapp/superbased-observer/internal/shimguard"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Cloud-agent connector wiring (docs/cloud-agents.md, plan section 5.1,
// CA-D5). This file is the one place the connectors' egress
// (internal/cloudagentsnet) and keychain are composed with the service,
// which owns no I/O of its own. tests/invariant/cloudagents_egress_test.go
// pins that only the service and this command import the egress package.

// cloudAgentsCredDir is the hardened file fallback for the keychain, next to
// the database (used only when the OS keychain is unusable). The CLI
// connectors never open it.
func cloudAgentsCredDir(cfg config.Config) string {
	return filepath.Join(filepath.Dir(cfg.Observer.DBPath), "cloudagents-cred")
}

// lazyCloudKeys opens the keychain on first use, so a daemon whose
// connectors store nothing never probes the OS keychain.
type lazyCloudKeys struct {
	once   sync.Once
	dir    string
	logger *slog.Logger
	s      keystore.Store
	opened atomic.Bool
}

func (k *lazyCloudKeys) store() keystore.Store {
	k.once.Do(func() {
		k.s = keystore.Open(cloudagentssvc.KeystoreService, k.dir, k.logger)
		k.opened.Store(true)
	})
	return k.s
}

// Get reads a secret (opens the keychain).
func (k *lazyCloudKeys) Get(name string) (string, error) { return k.store().Get(name) }

// Set stores a secret (opens the keychain).
func (k *lazyCloudKeys) Set(name, value string) error { return k.store().Set(name, value) }

// Delete removes a secret (opens the keychain).
func (k *lazyCloudKeys) Delete(name string) error { return k.store().Delete(name) }

// Backend names the backend without opening it.
func (k *lazyCloudKeys) Backend() string {
	if !k.opened.Load() {
		return "not opened"
	}
	return k.s.Backend()
}

// SecurityDiagnostic reports the backend's diagnostic (opens the keychain).
func (k *lazyCloudKeys) SecurityDiagnostic() string { return k.store().SecurityDiagnostic() }

// newCloudAgentsService composes the service over database.
func newCloudAgentsService(cfg config.Config, database *sql.DB, logger *slog.Logger) *cloudagentssvc.Service {
	home, _ := os.UserHomeDir()
	var exclude []string
	if home != "" {
		exclude = append(exclude, shimguard.DefaultShimDir(runtime.GOOS, home))
	}
	netOpts := cloudagentsnet.Options{Version: version, ExcludeDirs: exclude, Logger: logger}
	if cloudAgentsTestNet != nil {
		cloudAgentsTestNet(&netOpts)
	}
	client := cloudagentsnet.New(netOpts)
	var keys keystore.Store = &lazyCloudKeys{dir: cloudAgentsCredDir(cfg), logger: logger}
	if cloudAgentsTestKeys != nil {
		keys = cloudAgentsTestKeys
	}
	return cloudagentssvc.New(cloudagentssvc.Options{
		Store:  store.New(database),
		Net:    client,
		API:    client, // the same egress: one host table, one set of caps
		Keys:   keys,
		Logger: logger,
	})
}

// cloudAgentsTestNet and cloudAgentsTestKeys let the command tests point the
// real egress at an httptest server and use an in-memory keychain. Nil in
// every production path.
var (
	cloudAgentsTestNet  func(*cloudagentsnet.Options)
	cloudAgentsTestKeys keystore.Store
)

// processCloudAgents is the daemon's one service: the dashboard API and the
// poll loop share it, so one sync runs at a time and backoff has one owner.
var (
	processCloudAgentsMu  sync.Mutex
	processCloudAgentsSvc *cloudagentssvc.Service
)

func processCloudAgents(cfg config.Config, database *sql.DB, logger *slog.Logger) *cloudagentssvc.Service {
	processCloudAgentsMu.Lock()
	defer processCloudAgentsMu.Unlock()
	if processCloudAgentsSvc == nil {
		processCloudAgentsSvc = newCloudAgentsService(cfg, database, logger)
	}
	return processCloudAgentsSvc
}

// cloudAgentsLoop runs the poll loop until ctx ends. With no linked account
// it reads the local database once a minute and makes no vendor call.
// Fail-soft: a config or database error idles the loop, never the daemon.
func cloudAgentsLoop(ctx context.Context, configPath string) {
	cfg, database, cleanup, err := loadConfigAndDB(ctx, configPath)
	if err != nil {
		return
	}
	defer cleanup()
	processCloudAgents(cfg, database, newLogger(cfg.Observer.LogLevel)).Run(ctx)
}
